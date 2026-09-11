//! [`ProofRequestV2`]: a World ID proof request carrying an escrow payment authorisation.

use alloy::{
    signers::SignerSync,
    sol_types::{Eip712Domain, SolStruct as _},
};
use alloy_primitives::{Address, B256, Bytes, Uint};
use serde::{Deserialize, Serialize};
use world_id_primitives::{
    PrimitiveError,
    request::{ProofRequest, RequestVersion},
};

use crate::{
    nonce::{LaneNonce, NonceError},
    typed_data::PaymentAuthorizationTypedData,
};

/// The escrow's `uint96` channel nonce.
type U96 = Uint<96, 2>;

/// Errors raised while building, signing, or verifying a [`ProofRequestV2`].
#[derive(Debug, thiserror::Error)]
pub enum RequestV2Error {
    /// `inner.version` is not [`RequestVersion::V2`].
    #[error("proof request version must be 2, found {found}")]
    WrongVersion {
        /// The version actually carried by the request.
        found: u8,
    },
    /// Exactly one of `channel_id` / `channel_nonce` is present.
    #[error("a payment authorisation needs both `channel_id` and `channel_nonce`, or neither")]
    HalfPayment,
    /// The request carries no payment authorisation, so there is nothing to sign or verify.
    #[error("request carries no payment authorisation")]
    NoPayment,
    /// The channel nonce is malformed or out of range.
    #[error(transparent)]
    Nonce(#[from] NonceError),
    /// The inner request could not be digested.
    #[error(transparent)]
    Primitive(#[from] PrimitiveError),
    /// The signature is malformed or could not be recovered from.
    #[error("signature error: {0}")]
    Signature(String),
    /// The recovered signer is not the channel's `spendKey`.
    #[error("payment authorisation signed by {recovered}, expected spend key {expected}")]
    SignerMismatch {
        /// The channel's pinned `spendKey`.
        expected: Address,
        /// The address recovered from the signature.
        recovered: Address,
    },
}

/// One payment authorisation in the shape `IWorldIDFeeEscrow.PaymentAuthorization` expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnchainPaymentAuthorization {
    /// Packed `lane << 64 | counter`, ABI-encoded as `uint96`.
    pub channel_nonce: u128,
    /// `SHA256(0x01 || nonce || created_at || expires_at || action?)` of the inner request.
    pub rp_request_digest: B256,
    /// 65-byte `r || s || v` with `v ∈ {27, 28}`, the layout `OpenZeppelin`'s `ECDSA.recover` takes.
    pub signature: Bytes,
}

impl OnchainPaymentAuthorization {
    /// Lane this authorisation belongs to.
    #[must_use]
    pub fn lane(&self) -> u32 {
        LaneNonce::unpack(self.channel_nonce).map_or(0, |n| n.lane)
    }
}

/// A World ID proof request extended with an optional escrow payment authorisation.
///
/// The channel fields are flattened into the V1 JSON object, so a V2 request without a
/// payment is byte-identical to a V1 request except for `version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestV2 {
    /// The underlying World ID proof request. `inner.signature` holds the EIP-712 signature.
    #[serde(flatten)]
    pub inner: ProofRequest,
    /// Channel this request draws payment from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<B256>,
    /// Channel nonce authorising exactly one unit of paid work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_nonce: Option<LaneNonce>,
}

impl ProofRequestV2 {
    /// Wraps an existing request without a payment authorisation.
    #[must_use]
    pub const fn without_payment(inner: ProofRequest) -> Self {
        Self {
            inner,
            channel_id: None,
            channel_nonce: None,
        }
    }

    /// Returns the payment fields, or `None` when the request authorises no payment.
    ///
    /// # Errors
    /// Returns [`RequestV2Error::HalfPayment`] if only one of the two fields is present.
    pub const fn payment(&self) -> Result<Option<(B256, LaneNonce)>, RequestV2Error> {
        match (self.channel_id, self.channel_nonce) {
            (Some(channel_id), Some(nonce)) => Ok(Some((channel_id, nonce))),
            (None, None) => Ok(None),
            _ => Err(RequestV2Error::HalfPayment),
        }
    }

    /// Checks the version tag and the payment field pairing.
    ///
    /// # Errors
    /// Returns [`RequestV2Error::WrongVersion`] or [`RequestV2Error::HalfPayment`].
    pub fn validate(&self) -> Result<(), RequestV2Error> {
        if !matches!(self.inner.version, RequestVersion::V2) {
            return Err(RequestV2Error::WrongVersion {
                found: self.inner.version as u8,
            });
        }
        self.payment().map(|_| ())
    }

    /// Builds the EIP-712 payload for this request's payment, if it has one.
    ///
    /// # Errors
    /// Returns an error if the request is invalid or the inner digest cannot be computed.
    pub fn payment_authorization(
        &self,
    ) -> Result<Option<PaymentAuthorizationTypedData>, RequestV2Error> {
        self.validate()?;
        let Some((channel_id, nonce)) = self.payment()? else {
            return Ok(None);
        };
        Ok(Some(PaymentAuthorizationTypedData {
            channelId: channel_id,
            rpId: self.inner.rp_id.into_inner(),
            // `lane` and `counter` are exactly the two 32/64-bit halves of the uint96.
            channelNonce: U96::from_limbs([nonce.counter, u64::from(nonce.lane)]),
            rpRequestDigest: B256::from(self.inner.digest_hash()?),
        }))
    }

    /// EIP-712 signing hash of this request's payment authorisation.
    ///
    /// # Errors
    /// Returns [`RequestV2Error::NoPayment`] when there is no payment to sign. A V2 request
    /// without channel fields falls back to V1 signing rules, which this crate deliberately
    /// does not implement.
    pub fn signing_hash(&self, domain: &Eip712Domain) -> Result<B256, RequestV2Error> {
        let payload = self
            .payment_authorization()?
            .ok_or(RequestV2Error::NoPayment)?;
        Ok(payload.eip712_signing_hash(domain))
    }

    /// Signs `inner` as a V2 payment authorisation on `channel_id`.
    ///
    /// Overwrites `inner.version` with [`RequestVersion::V2`] and `inner.signature` with the
    /// EIP-712 signature; any signature already on `inner` is discarded.
    ///
    /// # Errors
    /// Returns an error if the digest cannot be computed or the signer fails.
    pub fn sign<S: SignerSync>(
        inner: ProofRequest,
        channel_id: B256,
        nonce: LaneNonce,
        signer: &S,
        domain: &Eip712Domain,
    ) -> Result<Self, RequestV2Error> {
        let mut request = Self {
            inner,
            channel_id: Some(channel_id),
            channel_nonce: Some(nonce),
        };
        request.inner.version = RequestVersion::V2;

        let hash = request.signing_hash(domain)?;
        request.inner.signature = signer
            .sign_hash_sync(&hash)
            .map_err(|e| RequestV2Error::Signature(e.to_string()))?;
        Ok(request)
    }

    /// Verifies the payment authorisation against the channel's pinned `spendKey`.
    ///
    /// This never falls back to the V1 EIP-191 rule (`recover_address_from_msg` over the raw
    /// RP signature message). A V2 request whose EIP-712 recovery fails is rejected outright;
    /// accepting the V1 form here would let an RP signature minted for a free request be
    /// replayed as a payment authorisation.
    ///
    /// # Errors
    /// Returns [`RequestV2Error::SignerMismatch`] on a foreign signer,
    /// [`RequestV2Error::Signature`] on a malformed signature, and the [`Self::validate`]
    /// errors otherwise.
    pub fn verify(
        &self,
        domain: &Eip712Domain,
        expected_spend_key: Address,
    ) -> Result<(), RequestV2Error> {
        let hash = self.signing_hash(domain)?;
        let recovered = self
            .inner
            .signature
            .recover_address_from_prehash(&hash)
            .map_err(|e| RequestV2Error::Signature(e.to_string()))?;
        if recovered != expected_spend_key {
            return Err(RequestV2Error::SignerMismatch {
                expected: expected_spend_key,
                recovered,
            });
        }
        Ok(())
    }

    /// Extracts the authorisation in the form `settle` takes.
    ///
    /// # Errors
    /// Returns [`RequestV2Error::NoPayment`] when the request authorises no payment.
    pub fn to_onchain_auth(&self) -> Result<OnchainPaymentAuthorization, RequestV2Error> {
        self.validate()?;
        let (_, nonce) = self.payment()?.ok_or(RequestV2Error::NoPayment)?;
        Ok(OnchainPaymentAuthorization {
            channel_nonce: nonce.pack(),
            rp_request_digest: B256::from(self.inner.digest_hash()?),
            signature: Bytes::from(self.inner.signature.as_bytes()),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "shared test helpers for sibling modules"
)]
pub(crate) mod tests {
    use super::*;
    use alloy::{
        signers::{Signature, local::PrivateKeySigner},
        uint,
    };
    use alloy_primitives::{address, b256};
    use k256::ecdsa::SigningKey;
    use world_id_primitives::{
        FieldElement, OprfKeyId, SessionRef,
        request::{ProofType, RequestItem},
        rp::RpId,
    };

    /// Escrow address used by every test domain.
    pub(crate) const ESCROW: Address = address!("0x6666666666666666666666666666666666666666");
    /// Chain id used by every test domain.
    pub(crate) const CHAIN_ID: u64 = 480;

    pub(crate) fn signer(byte: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_signing_key(
            SigningKey::from_bytes(&[byte; 32].into()).expect("valid test key"),
        )
    }

    pub(crate) fn test_domain() -> Eip712Domain {
        crate::typed_data::domain(CHAIN_ID, ESCROW)
    }

    /// A minimal V1 request with a placeholder signature.
    pub(crate) fn base_request(rp_id: u64, nonce: u64) -> ProofRequest {
        ProofRequest {
            id: format!("req_{nonce}"),
            version: RequestVersion::V1,
            proof_type: ProofType::Uniqueness,
            created_at: 1_700_000_000,
            expires_at: 1_700_100_000,
            rp_id: RpId::new(rp_id),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: SessionRef::None,
            action: Some(FieldElement::from(42u64)),
            signature: placeholder_signature(),
            nonce: FieldElement::from(nonce),
            requests: vec![RequestItem::new("orb".to_string(), 1, None, None, None)],
            constraints: None,
        }
    }

    fn placeholder_signature() -> Signature {
        signer(9).sign_message_sync(b"placeholder").expect("signs")
    }

    pub(crate) fn signed(
        spend_key: &PrivateKeySigner,
        channel_id: B256,
        nonce: LaneNonce,
        rp_id: u64,
        request_nonce: u64,
    ) -> ProofRequestV2 {
        ProofRequestV2::sign(
            base_request(rp_id, request_nonce),
            channel_id,
            nonce,
            spend_key,
            &test_domain(),
        )
        .expect("signs")
    }

    fn channel() -> B256 {
        b256!("0x00000000000000000000000000000000000000000000000000000000000000aa")
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = signer(1);
        let req = signed(&key, channel(), LaneNonce::new(1, 3), 7, 1);

        assert!(matches!(req.inner.version, RequestVersion::V2));
        assert_eq!(req.channel_id, Some(channel()));
        assert_eq!(req.channel_nonce, Some(LaneNonce::new(1, 3)));
        req.verify(&test_domain(), key.address()).expect("verifies");
    }

    #[test]
    fn verify_rejects_a_foreign_signer() {
        let req = signed(&signer(1), channel(), LaneNonce::new(0, 1), 7, 1);
        let err = req
            .verify(&test_domain(), signer(2).address())
            .expect_err("must reject");
        assert!(matches!(err, RequestV2Error::SignerMismatch { .. }));
    }

    #[test]
    fn verify_rejects_tampering() {
        let key = signer(1);
        let original = signed(&key, channel(), LaneNonce::new(1, 3), 7, 1);

        let mut swapped_channel = original.clone();
        swapped_channel.channel_id = Some(B256::ZERO);
        assert!(
            swapped_channel
                .verify(&test_domain(), key.address())
                .is_err()
        );

        let mut bumped_nonce = original.clone();
        bumped_nonce.channel_nonce = Some(LaneNonce::new(1, 4));
        assert!(bumped_nonce.verify(&test_domain(), key.address()).is_err());

        let mut other_digest = original.clone();
        other_digest.inner.nonce = FieldElement::from(999u64);
        assert!(other_digest.verify(&test_domain(), key.address()).is_err());

        let mut other_rp = original.clone();
        other_rp.inner.rp_id = RpId::new(8);
        assert!(other_rp.verify(&test_domain(), key.address()).is_err());

        let mut other_escrow = original;
        let foreign = crate::typed_data::domain(
            CHAIN_ID,
            address!("0x0000000000000000000000000000000000009999"),
        );
        other_escrow.inner.version = RequestVersion::V2;
        assert!(other_escrow.verify(&foreign, key.address()).is_err());
    }

    /// A V1 EIP-191 signature over the raw RP message must never satisfy V2 verification.
    #[test]
    fn v1_signature_does_not_satisfy_v2_verification() {
        use world_id_primitives::rp::compute_rp_signature_msg;

        let key = signer(1);
        let mut inner = base_request(7, 1);
        let msg = compute_rp_signature_msg(
            *inner.nonce,
            inner.created_at,
            inner.expires_at,
            inner.action.map(|a| *a),
        );
        inner.signature = key.sign_message_sync(&msg).expect("signs");
        inner.version = RequestVersion::V2;

        let req = ProofRequestV2 {
            inner,
            channel_id: Some(channel()),
            channel_nonce: Some(LaneNonce::new(0, 1)),
        };
        let err = req
            .verify(&test_domain(), key.address())
            .expect_err("V1 signature must not verify as V2");
        assert!(matches!(err, RequestV2Error::SignerMismatch { .. }));
    }

    #[test]
    fn half_a_payment_is_rejected() {
        let mut req = ProofRequestV2::without_payment(base_request(7, 1));
        req.inner.version = RequestVersion::V2;
        assert!(req.validate().is_ok(), "no payment at all is fine");

        req.channel_id = Some(channel());
        assert!(matches!(req.validate(), Err(RequestV2Error::HalfPayment),));

        req.channel_id = None;
        req.channel_nonce = Some(LaneNonce::new(0, 1));
        assert!(matches!(req.validate(), Err(RequestV2Error::HalfPayment),));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let req = ProofRequestV2 {
            inner: base_request(7, 1),
            channel_id: Some(channel()),
            channel_nonce: Some(LaneNonce::new(0, 1)),
        };
        assert!(matches!(
            req.validate(),
            Err(RequestV2Error::WrongVersion { found: 1 })
        ));
    }

    #[test]
    fn signing_hash_without_payment_is_an_error() {
        let mut req = ProofRequestV2::without_payment(base_request(7, 1));
        req.inner.version = RequestVersion::V2;
        assert!(matches!(
            req.signing_hash(&test_domain()),
            Err(RequestV2Error::NoPayment)
        ));
    }

    #[test]
    fn onchain_auth_is_65_bytes_with_eip155_free_parity() {
        let key = signer(1);
        let req = signed(&key, channel(), LaneNonce::new(1, 3), 7, 1);
        let auth = req.to_onchain_auth().expect("has payment");

        assert_eq!(auth.channel_nonce, LaneNonce::new(1, 3).pack());
        assert_eq!(auth.lane(), 1);
        assert_eq!(auth.signature.len(), 65);
        let v = auth.signature[64];
        assert!(v == 27 || v == 28, "OZ ECDSA.recover expects v in 27/28");
        assert_eq!(
            auth.rp_request_digest,
            B256::from(req.inner.digest_hash().unwrap())
        );
    }

    #[test]
    fn json_flattens_channel_fields_to_the_top_level() {
        let req = signed(&signer(1), channel(), LaneNonce::new(1, 3), 7, 1);
        let value: serde_json::Value = serde_json::to_value(&req).expect("serialises");
        let obj = value.as_object().expect("object");

        assert_eq!(obj["version"], 2);
        assert_eq!(obj["channel_id"], format!("{:#x}", channel()));
        assert_eq!(obj["channel_nonce"], "0x10000000000000003");
        assert!(obj.contains_key("proof_requests"), "inner keys stay flat");
        assert!(!obj.contains_key("inner"), "inner must not be nested");

        let decoded: ProofRequestV2 = serde_json::from_value(value).expect("deserialises");
        assert_eq!(decoded, req);
    }

    #[test]
    fn a_v2_request_without_payment_matches_the_v1_shape() {
        let mut v1 = base_request(7, 1);
        let v1_json = serde_json::to_value(&v1).expect("serialises");

        v1.version = RequestVersion::V2;
        let v2 = ProofRequestV2::without_payment(v1);
        let mut v2_json = serde_json::to_value(&v2).expect("serialises");

        assert_eq!(v2_json["version"], 2);
        v2_json["version"] = serde_json::json!(1);
        assert_eq!(v2_json, v1_json, "no extra keys when there is no payment");
    }
}
