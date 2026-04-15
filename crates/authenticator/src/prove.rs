use secrecy::ExposeSecret;
use world_id_primitives::{
    Credential, FieldElement, ProofRequest, ProofResponse, RequestItem, ResponseItem, SessionId,
    SessionNullifier, ZeroKnowledgeProof,
};
#[cfg(feature = "provekit")]
use world_id_proof::WhirR1CSProof;
use world_id_proof::{
    AuthenticatorProofInput, FullOprfOutput, OprfEntrypoint, proof::generate_nullifier_proof,
};

use crate::{
    api_types::AccountInclusionProof,
    authenticator::{Authenticator, CredentialInput, ProofResult},
    error::AuthenticatorError,
};
use world_id_primitives::TREE_DEPTH;

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
    async fn get_oprf_entrypoint(
        &self,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<OprfEntrypoint<'_>, AuthenticatorError> {
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

        let query_material = self
            .query_material
            .as_ref()
            .ok_or(AuthenticatorError::ProofMaterialsNotLoaded)?;

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
        let mut rng = rand::rngs::OsRng;

        let oprf_entrypoint = self.get_oprf_entrypoint(account_inclusion_proof).await?;

        Ok(oprf_entrypoint
            .gen_nullifier(&mut rng, proof_request)
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
        let oprf_entrypoint = self.get_oprf_entrypoint(None).await?;

        let (blinding_factor, _share_epoch) = oprf_entrypoint
            .gen_credential_blinding_factor(&mut rng, issuer_schema_id)
            .await?;

        Ok(blinding_factor)
    }

    /// Builds a [`SessionId`] object which can be used for Session Proofs. This has two uses:
    /// 1. Creating a new Sesssion, i.e. generating a [`SessionId`] for the first time.
    /// 2. Reconstructing a session for a Session Proof, particularly if the `session_id_r_seed` is not cached.
    ///
    /// Internally, this generates the session's random seed (`r`) using OPRF Nodes. This seed is used to
    /// compute the [`SessionId::commitment`] for Session Proofs.
    ///
    /// # Arguments
    /// - `proof_request`: the request received from the RP to initialize a session id.
    /// - `session_id_r_seed`: the seed (see below) if it was already generated previously and it's cached.
    /// - `account_inclusion_proof`: an optionally cached object can be passed to
    ///   avoid an additional network call. If not passed, it'll be fetched from the indexer.
    ///
    /// # Returns
    /// - `session_id`: The generated [`SessionId`] to be shared with the requesting RP.
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
        session_id_r_seed: Option<FieldElement>,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<(SessionId, FieldElement), AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        let oprf_seed = match proof_request.session_id {
            Some(session_id) => session_id.oprf_seed,
            None => SessionId::generate_oprf_seed(&mut rng),
        };

        let session_id_r_seed = match session_id_r_seed {
            Some(seed) => seed,
            None => {
                let entrypoint = self.get_oprf_entrypoint(account_inclusion_proof).await?;
                let oprf_output = entrypoint
                    .gen_session_id_r_seed(&mut rng, proof_request, oprf_seed)
                    .await?;
                oprf_output.verifiable_oprf_output.output.into()
            }
        };

        let session_id = SessionId::from_r_seed(self.leaf_index(), session_id_r_seed, oprf_seed)?;

        if let Some(request_session_id) = proof_request.session_id {
            if request_session_id != session_id {
                return Err(AuthenticatorError::SessionIdMismatch);
            }
        }

        Ok((session_id, session_id_r_seed))
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
    /// - `session_id_r_seed` — a cached session `r` seed for Session Proofs. If not available, it will be
    ///   re-computed.
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
        // 1. Determine request items to prove
        let available: std::collections::HashSet<u64> = credentials
            .iter()
            .map(|c| c.credential.issuer_schema_id)
            .collect();
        let items_to_prove = proof_request
            .credentials_to_prove(&available)
            .ok_or(AuthenticatorError::UnfullfilableRequest)?;

        // 2. Resolve session seed
        let resolved_session_seed = if proof_request.is_session_proof() {
            if let Some(seed) = session_id_r_seed {
                // Validate the cached seed produces the expected session ID
                let session_id = proof_request
                    .session_id
                    .expect("session proof must have session_id");

                let computed =
                    SessionId::from_r_seed(self.leaf_index(), seed, session_id.oprf_seed)?;

                if computed != session_id {
                    return Err(AuthenticatorError::SessionIdMismatch);
                }
                Some(seed)
            } else {
                let (_session_id, seed) = self
                    .build_session_id(proof_request, None, account_inclusion_proof)
                    .await?;
                Some(seed)
            }
        } else {
            None
        };

        // 3. Generate per-credential proofs for the selected items
        let creds_by_schema: std::collections::HashMap<u64, &CredentialInput> = credentials
            .iter()
            .map(|c| (c.credential.issuer_schema_id, c))
            .collect();

        let mut responses = Vec::with_capacity(items_to_prove.len());
        for request_item in &items_to_prove {
            let cred_input = creds_by_schema[&request_item.issuer_schema_id];

            let response_item = self.generate_credential_proof(
                nullifier.clone(),
                request_item,
                &cred_input.credential,
                cred_input.blinding_factor,
                resolved_session_seed,
                proof_request.session_id,
                proof_request.created_at,
            )?;
            responses.push(response_item);
        }

        // 4. Assemble response
        let proof_response = ProofResponse {
            id: proof_request.id.clone(),
            version: proof_request.version,
            session_id: proof_request.session_id,
            responses,
            error: None,
        };

        // 5. Validate and return response
        proof_request.validate_response(&proof_response)?;
        Ok(ProofResult {
            session_id_r_seed: resolved_session_seed,
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
    ///   For Uniqueness Proofs (when `session_id` is `None`), this value is ignored by the circuit.
    /// - `session_id`: The expected session ID provided by the RP. Only needed for Session Proofs. Obtained from the RP's [`ProofRequest`].
    /// - `request_timestamp`: The timestamp of the request. Obtained from the RP's [`ProofRequest`].
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[expect(clippy::too_many_arguments)]
    fn generate_credential_proof(
        &self,
        oprf_nullifier: FullOprfOutput,
        request_item: &RequestItem,
        credential: &Credential,
        credential_sub_blinding_factor: FieldElement,
        session_id_r_seed: Option<FieldElement>,
        session_id: Option<SessionId>,
        request_timestamp: u64,
    ) -> Result<ResponseItem, AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        let nullifier_material = self
            .nullifier_material
            .as_ref()
            .ok_or(AuthenticatorError::ProofMaterialsNotLoaded)?;

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
        let response_item = if session_id.is_some() {
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
    /// - `credential_blinding_factor`: The blinding factor generated for the credential.
    /// - `sub`: The expected `sub` of the Credential in question.
    /// - `account_inclusion_proof`: An optionally cached account inclusion proof. If not provided, a new inclusion proof will be fetched.
    ///
    /// # Returns
    /// - The Noir ZKP.
    /// - The root of the Merkle tree used for inclusion in the `WorldIDRegistry`.
    #[cfg(feature = "provekit")]
    pub async fn prove_credential_sub(
        &self,
        nonce: FieldElement,
        credential_blinding_factor: FieldElement,
        sub: FieldElement,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<(WhirR1CSProof, FieldElement), AuthenticatorError> {
        use world_id_proof::circuit_inputs::OwnershipProofCircuitInput;
        use world_id_proof::ownership_proof::generate_ownership_proof;

        let authenticator_input = self
            .prepare_authenticator_input(account_inclusion_proof)
            .await?;

        let commitment = Credential::compute_sub(self.leaf_index(), credential_blinding_factor);

        if commitment != sub {
            return Err(AuthenticatorError::InvalidSubOrBlindingFactor);
        }

        let signature = self
            .signer
            .offchain_signer_private_key()
            .expose_secret()
            .sign(*commitment);

        let input = OwnershipProofCircuitInput {
            key_index: authenticator_input.key_index,
            key_set: authenticator_input.key_set.clone(),
            inclusion_proof: authenticator_input.inclusion_proof.clone(),
            nonce,
            signature,
            commitment_blinder: credential_blinding_factor,
        };

        let proof = generate_ownership_proof(input)?;

        // TODO: Create a unified typed response (requires updates to ProveKit)
        Ok((proof.whir_r1cs_proof, proof.public_inputs.0[0].into()))
    }
}

#[cfg(test)]
#[cfg(feature = "provekit")]
mod tests {
    use crate::{
        authenticator::Authenticator,
        error::AuthenticatorError,
        service_client::{ServiceClient, ServiceKind},
    };
    use alloy::primitives::address;
    use ruint::aliases::U256;
    use taceo_oprf::client::Connector;
    use world_id_primitives::{
        Config, Credential, FieldElement, Signer, TREE_DEPTH, merkle::AccountInclusionProof,
    };
    use world_id_test_utils::fixtures::single_leaf_merkle_fixture;

    fn build_test_authenticator(
        seed: &[u8; 32],
        leaf_index: u64,
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
            "http://indexer.example.com".to_string(),
            "http://gateway.example.com".to_string(),
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
                config.indexer_url(),
                None,
            )
            .expect("valid indexer client"),
            gateway_client: ServiceClient::new(
                http_client,
                ServiceKind::Gateway,
                config.gateway_url(),
                None,
            )
            .expect("valid gateway client"),
            ws_connector: Connector::Plain,
            query_material: None,
            nullifier_material: None,
        };

        (authenticator, account_inclusion_proof)
    }

    #[tokio::test]
    async fn test_prove_credential_sub_rejects_wrong_sub() {
        let leaf_index = 1u64;
        let (authenticator, inclusion_proof) = build_test_authenticator(&[42u8; 32], leaf_index);

        let blinding_factor = FieldElement::from(999u64);
        let wrong_sub = FieldElement::from(123u64);

        let result = authenticator
            .prove_credential_sub(
                FieldElement::from(1_234_567_890u64),
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
    async fn test_prove_credential_sub_succeeds_with_correct_sub() {
        let leaf_index = 1u64;
        let (authenticator, inclusion_proof) = build_test_authenticator(&[42u8; 32], leaf_index);

        let blinding_factor = FieldElement::from(999u64);
        let correct_sub = Credential::compute_sub(leaf_index, blinding_factor);
        let nonce = FieldElement::from(1_234_567_890u64);

        authenticator
            .prove_credential_sub(nonce, blinding_factor, correct_sub, Some(inclusion_proof))
            .await
            .expect("proof generation should succeed");
    }
}
