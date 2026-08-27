use secrecy::ExposeSecret;
use world_id_primitives::{
    Credential, FieldElement, ProofRequest, ProofResponse, ProofType, RequestItem, ResponseItem,
    SessionId, SessionNullifier, SessionRef, ZeroKnowledgeProof, request::RpAuthorizationProof,
};
use world_id_proof::{
    AuthenticatorProofInput, FullOprfOutput, OprfEntrypoint, ProofCompression,
    nullifier_proof::{CircomGroth16Material, generate_nullifier_proof},
};

use crate::{
    api_types::AccountInclusionProof,
    authenticator::{Authenticator, CredentialInput, ProofResult},
    error::AuthenticatorError,
};
#[cfg(not(target_arch = "wasm32"))]
use world_id_primitives::OwnershipProof;
use world_id_primitives::TREE_DEPTH;
#[cfg(not(target_arch = "wasm32"))]
use world_id_proof::{
    circuit_inputs::OwnershipProofCircuitInput,
    ownership_proof::generate_ownership_proof_with_prover,
};

#[expect(unused_imports, reason = "used for docs")]
use world_id_primitives::Nullifier;

impl Authenticator {
    /// Gets an object to request OPRF computations to OPRF Nodes.
    ///
    /// # Arguments
    /// - `account_inclusion_proof`: an optionally cached object can be passed to
    ///   avoid an additional network call. If not passed, it'll be fetched from the indexer.
    ///
    /// # Errors
    /// - Will return an error if there are no OPRF Nodes configured or if the threshold is invalid.
    /// - Will return an error if proof materials are not loaded.
    /// - Will return an error if there are issues fetching an inclusion proof.
    async fn get_oprf_entrypoint<'a>(
        &'a self,
        query_material: &'a CircomGroth16Material,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<OprfEntrypoint<'a>, AuthenticatorError> {
        // Check OPRF Config
        let services = self.config.nullifier_oracle_urls();
        if services.is_empty() {
            return Err(AuthenticatorError::Generic(
                "No nullifier oracle URLs configured".to_string(),
            ));
        }
        let requested_threshold = self.config.nullifier_oracle_threshold();
        if requested_threshold == 0 {
            return Err(AuthenticatorError::InvalidConfig {
                attribute: "nullifier_oracle_threshold".to_string(),
                reason: "must be at least 1".to_string(),
            });
        }
        let threshold = requested_threshold.min(services.len());

        let authenticator_input = self
            .prepare_authenticator_input(account_inclusion_proof)
            .await?;

        Ok(OprfEntrypoint::new(
            services,
            threshold,
            query_material,
            authenticator_input,
            &self.ws_connector,
        ))
    }

    async fn prepare_authenticator_input(
        &self,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<AuthenticatorProofInput, AuthenticatorError> {
        // Fetch inclusion_proof && authenticator key_set if not provided
        let account_inclusion_proof = if let Some(account_inclusion_proof) = account_inclusion_proof
        {
            account_inclusion_proof
        } else {
            self.fetch_inclusion_proof().await?
        };

        let key_index = account_inclusion_proof
            .authenticator_pubkeys
            .iter()
            .position(|pk| {
                pk.as_ref()
                    .is_some_and(|pk| pk.pk == self.offchain_pubkey().pk)
            })
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

        let authenticator_input = AuthenticatorProofInput::new(
            account_inclusion_proof.authenticator_pubkeys,
            account_inclusion_proof.inclusion_proof,
            self.signer
                .offchain_signer_private_key()
                .expose_secret()
                .clone(),
            key_index,
        );

        Ok(authenticator_input)
    }

    /// Generates a nullifier for a World ID Proof (through OPRF Nodes).
    ///
    /// A [`Nullifier`] is a unique, one-time use, anonymous identifier for a World ID
    /// on a specific RP context. See [`Nullifier`] for more details.
    ///
    /// # Arguments
    /// - `proof_request`: the request received from the RP.
    /// - `account_inclusion_proof`: an optionally cached object can be passed to
    ///   avoid an additional network call. If not passed, it'll be fetched from the indexer.
    ///
    /// A Nullifier takes an `action` as input:
    /// - If `proof_request` is for a Session Proof, a random internal `action` is generated. This
    ///   is opaque to RPs, and verified internally in the verification contract.
    /// - If `proof_request` is for a Uniqueness Proof, the `action` is provided by the RP,
    ///   if not provided a default of [`FieldElement::ZERO`] is used.
    ///
    /// # Errors
    ///
    /// - Will raise a [`ProofError`](world_id_proof::ProofError) if there is any issue
    ///   generating the nullifier. For example, network issues, unexpected incorrect responses
    ///   from OPRF Nodes.
    /// - Raises an error if the OPRF Nodes configuration is not correctly set.
    pub async fn generate_nullifier(
        &self,
        proof_request: &ProofRequest,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<FullOprfOutput, AuthenticatorError> {
        self.generate_nullifier_with_authorization(proof_request, account_inclusion_proof, None)
            .await
    }

    /// Generates a [`Nullifier`] for an RP whose authorization is not a plain EOA signature.
    ///
    /// Behaves exactly like [`Self::generate_nullifier`], except that the RP's proof of
    /// authorization is supplied explicitly.
    ///
    /// # Arguments
    /// - `authorization_proof`: [`None`] uses the EOA signature carried on `proof_request`.
    ///   Contract-backed RP signers MUST pass [`RpAuthorizationProof::Wip101`], since OPRF
    ///   nodes reject an EOA authorization proof for a contract signer.
    ///
    /// # Errors
    ///
    /// Same as [`Self::generate_nullifier`].
    pub async fn generate_nullifier_with_authorization(
        &self,
        proof_request: &ProofRequest,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
        authorization_proof: Option<RpAuthorizationProof>,
    ) -> Result<FullOprfOutput, AuthenticatorError> {
        proof_request.validate_proof_type()?;
        let mut rng = rand::rngs::OsRng;

        let query_material = self
            .zk_artifact_source
            .query_material()
            .map_err(AuthenticatorError::ZkArtifactError)?;
        let oprf_entrypoint = self
            .get_oprf_entrypoint(&query_material, account_inclusion_proof)
            .await?;

        Ok(oprf_entrypoint
            .gen_nullifier(&mut rng, proof_request, authorization_proof)
            .await?)
    }

    /// Generates a blinding factor for a Credential sub (through OPRF Nodes). The credential
    /// blinding factor enables every credential to have a different subject identifier, see
    /// [`Credential::sub`] for more details.
    ///
    /// # Errors
    ///
    /// - Will raise a [`ProofError`](world_id_proof::ProofError) if there is any issue
    ///   generating the blinding factor. For example, network issues, unexpected incorrect
    ///   responses from OPRF Nodes.
    /// - Raises an error if the OPRF Nodes configuration is not correctly set.
    pub async fn generate_credential_blinding_factor(
        &self,
        issuer_schema_id: u64,
    ) -> Result<FieldElement, AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        // This is called sporadic enough that fetching fresh is reasonable
        let query_material = self
            .zk_artifact_source
            .query_material()
            .map_err(AuthenticatorError::ZkArtifactError)?;
        let oprf_entrypoint = self.get_oprf_entrypoint(&query_material, None).await?;

        let (blinding_factor, _share_epoch) = oprf_entrypoint
            .gen_credential_blinding_factor(&mut rng, issuer_schema_id)
            .await?;

        Ok(blinding_factor)
    }

    /// Builds or resolves a [`SessionId`] object which can be used for Session Proofs. This has two uses:
    /// 1. Creating a new Session, i.e. generating a [`SessionId`] for the first time.
    /// 2. Reconstructing a session for a Session Proof, particularly if the `session_id_r_seed` is not cached.
    ///
    /// Internally, this derives the session randomness (`r`) using OPRF Nodes. For existing
    /// sessions this re-derives the same `r` from [`SessionId::oprf_seed`]; it does not mint a
    /// new session. The seed is used to compute the [`SessionId::commitment`] for Session Proofs.
    ///
    /// # Arguments
    /// - `proof_request`: the request received from the RP to create or prove a session id.
    /// - `session_id_r_seed`: the seed (see below) if it was already generated previously and it's cached.
    /// - `account_inclusion_proof`: an optionally cached object can be passed to
    ///   avoid an additional network call. If not passed, it'll be fetched from the indexer.
    ///
    /// # Returns
    /// - `session_id`: The generated or resolved [`SessionId`].
    /// - `session_id_r_seed`: The `r` value used for this session so the Authenticator can cache it.
    ///
    /// # Seed (`session_id_r_seed`)
    /// - If a `session_id_r_seed` (`r`) is not provided, it'll be derived/re-derived with the OPRF nodes.
    /// - Even if `r` has been generated before, the same `r` will be computed again for the same
    ///   context (i.e. `rpId`, [`SessionId::oprf_seed`]). This means caching `r` is optional but RECOMMENDED.
    /// -  Caching behavior is the responsibility of the Authenticator (and/or its relevant SDKs), not this crate.
    /// - More information about the seed can be found in [`SessionId::from_r_seed`].
    pub async fn build_session_id(
        &self,
        proof_request: &ProofRequest,
        cached_session_id_r_seed: Option<FieldElement>,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<(SessionId, FieldElement), AuthenticatorError> {
        self.build_session_id_with_authorization(
            proof_request,
            cached_session_id_r_seed,
            account_inclusion_proof,
            None,
        )
        .await
    }

    /// Builds or resolves a [`SessionId`] for an RP whose authorization is not a plain EOA
    /// signature.
    ///
    /// Behaves exactly like [`Self::build_session_id`], except that the RP's proof of
    /// authorization is supplied explicitly.
    ///
    /// # Arguments
    /// - `authorization_proof`: [`None`] uses the EOA signature carried on `proof_request`.
    ///   Contract-backed RP signers MUST pass [`RpAuthorizationProof::Wip101`], since OPRF
    ///   nodes reject an EOA authorization proof for a contract signer.
    ///
    /// # Errors
    ///
    /// Same as [`Self::build_session_id`].
    pub async fn build_session_id_with_authorization(
        &self,
        proof_request: &ProofRequest,
        cached_session_id_r_seed: Option<FieldElement>,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
        authorization_proof: Option<RpAuthorizationProof>,
    ) -> Result<(SessionId, FieldElement), AuthenticatorError> {
        proof_request.validate_proof_type()?;
        let mut rng = rand::rngs::OsRng;

        let oprf_seed = match proof_request.session_id {
            SessionRef::Existing(session_id) => session_id.oprf_seed,
            SessionRef::Create => SessionId::generate_oprf_seed(&mut rng),
            SessionRef::None => {
                return Err(AuthenticatorError::PrimitiveError(
                    world_id_primitives::PrimitiveError::InvalidInput {
                        attribute: "session_id".to_string(),
                        reason: "session_id must be \"create\" or an existing session id"
                            .to_string(),
                    },
                ));
            }
        };

        let resolved_session_id_r_seed = match cached_session_id_r_seed {
            Some(seed) => seed,
            None => {
                let query_material = self
                    .zk_artifact_source
                    .query_material()
                    .map_err(AuthenticatorError::ZkArtifactError)?;
                let entrypoint = self
                    .get_oprf_entrypoint(&query_material, account_inclusion_proof)
                    .await?;
                let oprf_output = entrypoint
                    .derive_session_id_r_seed(
                        &mut rng,
                        proof_request,
                        oprf_seed,
                        authorization_proof,
                    )
                    .await?;
                oprf_output.verifiable_oprf_output.output.into()
            }
        };

        let session_id =
            SessionId::from_r_seed(self.leaf_index(), resolved_session_id_r_seed, oprf_seed)?;

        // Verify that the resolved (cached or freshly derived) matches the request session id.
        if let SessionRef::Existing(request_session_id) = proof_request.session_id {
            request_session_id.verify_commitment(self.leaf_index(), resolved_session_id_r_seed)?;
        }

        Ok((session_id, resolved_session_id_r_seed))
    }

    /// Generates a complete [`ProofResponse`] for
    /// the given [`ProofRequest`] to respond to an RP request.
    ///
    /// This orchestrates session resolution, per-credential proof generation,
    /// response assembly, and self-validation.
    ///
    /// # Typical flow
    /// ```rust,ignore
    /// // <- check request can be fulfilled with available credentials
    /// let nullifier = authenticator.generate_nullifier(&request, None).await?;
    /// // <- check replay guard using nullifier.oprf_output()
    /// let (response, meta) = authenticator.generate_proof(&request, nullifier, &creds, ...).await?;
    /// // <- cache `session_id_r_seed` (to speed future proofs) and `nullifier` (to prevent replays)
    /// ```
    ///
    /// # Arguments
    /// - `proof_request` — the RP's full request.
    /// - `nullifier` — the OPRF nullifier output, obtained from
    ///   [`generate_nullifier`](Self::generate_nullifier). The caller MUST check
    ///   for replays before calling this method to avoid wasted computation.
    /// - `credentials` — one [`CredentialInput`] per credential to prove,
    ///   matched to request items by `issuer_schema_id`.
    /// - `account_inclusion_proof` — a cached inclusion proof if available (a fresh one will be fetched otherwise)
    /// - `session_id_r_seed` — a cached session `r` seed. For requests using an existing
    ///   session it is re-derived if unavailable. Create flows mint a fresh session and return
    ///   the new `session_id_r_seed` for caching.
    ///
    /// # Caller Responsibilities
    /// 1. The caller must ensure the request can be fulfilled with the credentials which the user has available,
    ///    and provide such credentials.
    /// 2. The caller must ensure the nullifier has not been used before.
    ///
    /// # Errors
    /// - [`AuthenticatorError::UnfullfilableRequest`] if the provided credentials
    ///   cannot satisfy the request (including constraints).
    /// - Other `AuthenticatorError` variants on proof circuit or validation failures.
    pub async fn generate_proof(
        &self,
        proof_request: &ProofRequest,
        nullifier: FullOprfOutput,
        credentials: &[CredentialInput],
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
        session_id_r_seed: Option<FieldElement>,
    ) -> Result<ProofResult, AuthenticatorError> {
        proof_request.validate_proof_type()?;

        // 1. Determine request items to prove
        let available: std::collections::HashSet<u64> = credentials
            .iter()
            .map(|c| c.credential.issuer_schema_id)
            .collect();
        let items_to_prove = proof_request
            .credentials_to_prove(&available)
            .ok_or(AuthenticatorError::UnfullfilableRequest)?;

        // 2. Resolve session seed
        let (resolved_session_id, resolved_session_r_seed) = match proof_request.session_id {
            SessionRef::None => (None, None),
            SessionRef::Create => {
                let (session_id, seed) = self
                    .build_session_id(proof_request, None, account_inclusion_proof)
                    .await?;
                (Some(session_id), Some(seed))
            }
            SessionRef::Existing(session_id) => {
                if let Some(seed) = session_id_r_seed {
                    session_id.verify_commitment(self.leaf_index(), seed)?;
                    (Some(session_id), Some(seed))
                } else {
                    // Re-derive the same `r` from the existing session's `oprf_seed` when the
                    // caller did not provide a cached seed.
                    let (_session_id, seed) = self
                        .build_session_id(proof_request, None, account_inclusion_proof)
                        .await?;
                    (Some(session_id), Some(seed))
                }
            }
        };

        let nullifier_material = self
            .zk_artifact_source
            .nullifier_material()
            .map_err(AuthenticatorError::ZkArtifactError)?;

        // 3. Generate per-credential proofs for the selected items
        let creds_by_schema: std::collections::HashMap<u64, &CredentialInput> = credentials
            .iter()
            .map(|c| (c.credential.issuer_schema_id, c))
            .collect();

        let mut responses = Vec::with_capacity(items_to_prove.len());
        for request_item in &items_to_prove {
            let cred_input = creds_by_schema[&request_item.issuer_schema_id];

            let response_item = self.generate_credential_proof(
                &nullifier_material,
                nullifier.clone(),
                request_item,
                &cred_input.credential,
                cred_input.blinding_factor,
                resolved_session_r_seed,
                resolved_session_id,
                proof_request.proof_type,
                proof_request.created_at,
            )?;
            responses.push(response_item);
        }

        // 4. Assemble response
        let proof_response = ProofResponse {
            id: proof_request.id.clone(),
            version: proof_request.version,
            session_id: resolved_session_id,
            responses,
            error: None,
        };

        // 5. Validate and return response
        proof_request.validate_response(&proof_response)?;
        Ok(ProofResult {
            session_id_r_seed: resolved_session_r_seed,
            proof_response,
        })
    }

    /// Generates a single World ID Proof from a provided `[ProofRequest]` and `[Credential]`. This
    /// method generates the raw proof to be translated into a Uniqueness Proof or a Session Proof for the RP.
    ///
    /// The correct entrypoint for an RP request is [`Self::generate_proof`].
    ///
    /// This assumes the RP's `[ProofRequest]` has already been parsed to determine
    /// which `[Credential]` is appropriate for the request. This method responds to a
    /// specific `[RequestItem]` (a `[ProofRequest]` may contain multiple items).
    ///
    /// # Arguments
    /// - `oprf_nullifier`: The output representing the nullifier, generated from the `generate_nullifier` function. All proofs
    ///   require this attribute.
    /// - `request_item`: The specific `RequestItem` that is being resolved from the RP's `ProofRequest`.
    /// - `credential`: The Credential to be used for the proof that fulfills the `RequestItem`.
    /// - `credential_sub_blinding_factor`: The blinding factor for the Credential's sub.
    /// - `session_id_r_seed`: The session ID random seed, obtained via [`build_session_id`](Self::build_session_id).
    ///   For unbound Uniqueness Proofs (when `session_id` is `None`), this value is ignored by the circuit.
    /// - `session_id`: The expected session ID provided by the RP. Needed for Session Proofs and
    ///   session-bound Uniqueness Proofs. Obtained from the RP's [`ProofRequest`].
    /// - `proof_type`: Determines whether a Session or Uniqueness response item is produced.
    /// - `request_timestamp`: The timestamp of the request. Obtained from the RP's [`ProofRequest`].
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[expect(clippy::too_many_arguments)]
    fn generate_credential_proof(
        &self,
        nullifier_material: &CircomGroth16Material,
        oprf_nullifier: FullOprfOutput,
        request_item: &RequestItem,
        credential: &Credential,
        credential_sub_blinding_factor: FieldElement,
        session_id_r_seed: Option<FieldElement>,
        session_id: Option<SessionId>,
        proof_type: ProofType,
        request_timestamp: u64,
    ) -> Result<ResponseItem, AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        let merkle_root: FieldElement = oprf_nullifier.query_proof_input.merkle_root.into();
        let action_from_query: FieldElement = oprf_nullifier.query_proof_input.action.into();

        let expires_at_min = request_item.effective_expires_at_min(request_timestamp);

        let (proof, _public_inputs, nullifier) = generate_nullifier_proof(
            nullifier_material,
            &mut rng,
            credential,
            credential_sub_blinding_factor,
            oprf_nullifier,
            request_item,
            session_id.map(|v| v.commitment),
            session_id_r_seed,
            expires_at_min,
        )?;

        let proof = ZeroKnowledgeProof::from_groth16_proof(&proof, merkle_root);

        // Construct the appropriate response item based on proof type
        let nullifier_fe: FieldElement = nullifier.into();
        let response_item = if proof_type.is_session() {
            let session_nullifier = SessionNullifier::new(nullifier_fe, action_from_query)?;
            ResponseItem::new_session(
                request_item.identifier.clone(),
                request_item.issuer_schema_id,
                proof,
                session_nullifier,
                expires_at_min,
            )
        } else {
            ResponseItem::new_uniqueness(
                request_item.identifier.clone(),
                request_item.issuer_schema_id,
                proof,
                nullifier_fe.into(),
                expires_at_min,
            )
        };

        Ok(response_item)
    }

    /// Generates an Ownership Proof (WIP-103) over a Credential's `sub`.
    ///
    /// This proof MUST only be shared with each relevant issuer. This is the responsibility of Authenticators.
    ///
    /// # Arguments
    /// - `nonce`: The nonce of the request provided by the Issuer.
    /// - `context`: Identifies the specific operation which the user is performing with the issuer. Provided by the issuer, it is
    ///   RECOMMENDED to use a hashing function to lower arbitrary bytes into the field avoiding collisions, e.g. [`FieldElement::from_arbitrary_raw_bytes`]
    /// - `credential_blinding_factor`: The blinding factor generated for the credential.
    /// - `sub`: The expected `sub` of the Credential in question.
    /// - `account_inclusion_proof`: An optionally cached account inclusion proof. If not provided, a new inclusion proof will be fetched.
    ///
    /// # Returns
    /// The [`OwnershipProof`] containing the ZKP and Merkle root.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn prove_credential_sub(
        &self,
        nonce: FieldElement,
        context: FieldElement,
        credential_blinding_factor: FieldElement,
        sub: FieldElement,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<OwnershipProof, AuthenticatorError> {
        use world_id_primitives::poseidon::{self, ds};

        let authenticator_input = self
            .prepare_authenticator_input(account_inclusion_proof)
            .await?;

        let commitment = Credential::compute_sub(self.leaf_index(), credential_blinding_factor);

        if commitment != sub {
            return Err(AuthenticatorError::InvalidSubOrBlindingFactor);
        }

        let message = poseidon::hash(ds::OWNERSHIP_PROOF, [commitment, nonce, context]);

        let signature = self
            .signer
            .offchain_signer_private_key()
            .expose_secret()
            .sign(*message);

        let input = OwnershipProofCircuitInput {
            key_index: authenticator_input.key_index,
            key_set: authenticator_input.key_set.clone(),
            inclusion_proof: authenticator_input.inclusion_proof.clone(),
            nonce,
            expected_commitment: commitment,
            context,
            signature,
            commitment_blinder: credential_blinding_factor,
        };

        let prover = self
            .zk_artifact_source
            .ownership_prover()
            .map_err(AuthenticatorError::ZkArtifactError)?;

        Ok(generate_ownership_proof_with_prover(input, prover)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        authenticator::Authenticator,
        error::AuthenticatorError,
        service_client::{ServiceClient, ServiceKind},
    };
    use alloy::primitives::{B256, Signature, address};
    use ruint::{aliases::U256, uint};
    use std::sync::Arc;
    use taceo_oprf::client::Connector;
    use world_id_primitives::{
        Config, FieldElement, OprfKeyId, PrimitiveError, ProofRequest, ProofType, ServiceEndpoint,
        SessionId, SessionRef, Signer, TREE_DEPTH, merkle::AccountInclusionProof,
        request::RequestVersion, rp::RpId,
    };
    use world_id_proof::artifacts::{ZkArtifactSource, dummy::DummyZkArtifactSource};
    use world_id_test_utils::fixtures::single_leaf_merkle_fixture;

    fn build_test_authenticator(
        seed: &[u8; 32],
        leaf_index: u64,
        zk_artifact_source: Arc<dyn ZkArtifactSource>,
    ) -> (Authenticator, AccountInclusionProof<TREE_DEPTH>) {
        let signer = Signer::from_seed_bytes(seed).expect("valid seed");
        let pubkey = signer.offchain_signer_pubkey();

        let fixture =
            single_leaf_merkle_fixture(vec![pubkey], leaf_index).expect("valid merkle fixture");
        let account_inclusion_proof =
            AccountInclusionProof::new(fixture.inclusion_proof, fixture.key_set);

        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct("http://indexer.example.com".to_string()),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .expect("valid config");

        let http_client = reqwest::Client::new();
        let authenticator = Authenticator {
            config: config.clone(),
            packed_account_data: U256::from(leaf_index),
            signer,
            registry: None,
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )
            .expect("valid indexer client"),
            gateway_client: ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())
                .expect("valid gateway client"),
            ws_connector: Connector::Plain,
            zk_artifact_source,
        };

        (authenticator, account_inclusion_proof)
    }

    fn existing_session_request(session_id: SessionId) -> ProofRequest {
        ProofRequest {
            id: "test-request".to_string(),
            version: RequestVersion::V1,
            request_salt: B256::repeat_byte(0x42),
            proof_type: ProofType::Session,
            created_at: 1,
            expires_at: 2,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: SessionRef::Existing(session_id),
            action: None,
            signature: Signature::new(U256::ZERO, U256::ZERO, false),
            nonce: FieldElement::from(1u64),
            requests: Vec::new(),
            constraints: None,
        }
    }

    #[tokio::test]
    async fn test_build_session_id_accepts_matching_cached_seed() {
        let leaf_index = 1u64;
        let r_seed = FieldElement::from(123u64);
        let oprf_seed = SessionId::generate_oprf_seed(&mut rand::rngs::OsRng);
        let expected_session_id =
            SessionId::from_r_seed(leaf_index, r_seed, oprf_seed).expect("valid session id");
        let request = existing_session_request(expected_session_id);
        let (authenticator, _) =
            build_test_authenticator(&[42u8; 32], leaf_index, Arc::new(DummyZkArtifactSource));

        let (session_id, resolved_r_seed) = authenticator
            .build_session_id(&request, Some(r_seed), None)
            .await
            .expect("matching cached seed should be accepted");

        assert_eq!(session_id, expected_session_id);
        assert_eq!(resolved_r_seed, r_seed);
    }

    #[tokio::test]
    async fn test_build_session_id_rejects_mismatched_cached_seed() {
        let leaf_index = 1u64;
        let r_seed = FieldElement::from(123u64);
        let oprf_seed = SessionId::generate_oprf_seed(&mut rand::rngs::OsRng);
        let session_id =
            SessionId::from_r_seed(leaf_index, r_seed, oprf_seed).expect("valid session id");
        let request = existing_session_request(session_id);
        let (authenticator, _) =
            build_test_authenticator(&[42u8; 32], leaf_index, Arc::new(DummyZkArtifactSource));

        let error = authenticator
            .build_session_id(&request, Some(FieldElement::from(124u64)), None)
            .await
            .expect_err("mismatched cached seed should be rejected");

        assert!(matches!(
            error,
            AuthenticatorError::PrimitiveError(PrimitiveError::SessionIdCommitmentMismatch)
        ));
    }

    #[tokio::test]
    async fn test_prove_credential_sub_rejects_wrong_sub() {
        let leaf_index = 1u64;
        let (authenticator, inclusion_proof) =
            build_test_authenticator(&[42u8; 32], leaf_index, Arc::new(DummyZkArtifactSource));

        let blinding_factor = FieldElement::from(999u64);
        let wrong_sub = FieldElement::from(123u64);

        let result = authenticator
            .prove_credential_sub(
                FieldElement::from(1_234_567_890u64),
                FieldElement::from(42u64),
                blinding_factor,
                wrong_sub,
                Some(inclusion_proof),
            )
            .await;

        assert!(matches!(
            result,
            Err(AuthenticatorError::InvalidSubOrBlindingFactor)
        ));
    }

    #[tokio::test]
    #[cfg(all(
        not(target_arch = "wasm32"),
        feature = "embed-zkeys",
        feature = "embed-ownership-prover"
    ))]
    async fn test_prove_credential_sub_succeeds_with_correct_sub() {
        use world_id_primitives::Credential;
        use world_id_proof::artifacts::{ZkArtifactSourceExt as _, embedded::EmbeddedZkArtifacts};

        let leaf_index = 1u64;
        let zk_artifact_source = EmbeddedZkArtifacts.cached();
        let (authenticator, inclusion_proof) =
            build_test_authenticator(&[42u8; 32], leaf_index, Arc::new(zk_artifact_source));

        let blinding_factor = FieldElement::from(999u64);
        let correct_sub = Credential::compute_sub(leaf_index, blinding_factor);
        let nonce = FieldElement::from(1_234_567_890u64);
        let context = FieldElement::from(42u64);

        authenticator
            .prove_credential_sub(
                nonce,
                context,
                blinding_factor,
                correct_sub,
                Some(inclusion_proof),
            )
            .await
            .expect("proof generation should succeed");
    }
}
