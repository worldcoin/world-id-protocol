//! EIP-712 typed data for the `WorldIDFeeEscrow` contract.
//!
//! One domain, two structs. The type strings below are normative: they must stay
//! byte-identical to the contract's `CHANNEL_SETTINGS_TYPEHASH` and
//! `PAYMENT_AUTHORIZATION_TYPEHASH`.

use alloy::{
    signers::{Signature, SignerSync},
    sol_types::{Eip712Domain, SolStruct as _, eip712_domain},
};
use alloy_primitives::{Address, B256};

use crate::nonce::LaneNonce;

/// These live in a private module so the EIP-712 payloads are not mistaken for contract call
/// bindings. They are used only for hashing, signing, and recovery.
mod sol_types {
    use alloy::sol;

    sol! {
        /// Immutable channel terms. Never signed; its EIP-712 digest is the channel id.
        #[derive(Debug)]
        struct ChannelSettings {
            uint64 rpId;
            address spendKey;
            address collector;
            address token;
            uint256 pricePerUnit;
            uint64 epochLength;
            uint64 epochZero;
            bytes32 salt;
        }

        /// One unit of paid work, signed by the channel's `spendKey`.
        ///
        /// Names a channel, an epoch, and a lane counter, and nothing else. Binding an
        /// authorisation to a particular request is deferred to a later version of the
        /// protocol, which would add the paid request's digest as a fourth field.
        #[derive(Debug)]
        struct PaymentAuthorization {
            bytes32 channelId;
            uint64 epoch;
            uint96 channelNonce;
        }
    }
}

/// Immutable channel terms, `IWorldIDFeeEscrow.ChannelSettings`.
pub type ChannelSettings = sol_types::ChannelSettings;
/// EIP-712 payload the `spendKey` signs once per paid request.
pub type PaymentAuthorization = sol_types::PaymentAuthorization;

/// Errors raised while recovering a signer from a payment authorisation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoverError {
    /// `s` is above `secp256k1n / 2`, so the signature has a malleable twin.
    #[error("signature is not canonical: high s")]
    HighS,
    /// `r` or `s` is zero, which no honest signer produces.
    #[error("signature has a zero r or s component")]
    ZeroComponent,
    /// The curve operation failed.
    #[error("signature recovery failed: {0}")]
    Failed(String),
    /// Recovery produced the zero address.
    #[error("signature recovered the zero address")]
    ZeroAddress,
}

/// EIP-712 domain of the escrow deployed at `escrow` on `chain_id`.
#[must_use]
pub const fn domain(chain_id: u64, escrow: Address) -> Eip712Domain {
    eip712_domain!(
        name: "WorldIDFeeEscrow",
        version: "1",
        chain_id: chain_id,
        verifying_contract: escrow,
    )
}

impl ChannelSettings {
    /// The channel id: the EIP-712 signing hash of these settings.
    ///
    /// Never signed by anyone. It commits to the chain, the escrow, and every setting, so an
    /// authorisation naming it cannot be replayed against a channel on different terms.
    #[must_use]
    pub fn channel_id(&self, domain: &Eip712Domain) -> B256 {
        self.eip712_signing_hash(domain)
    }
}

impl PaymentAuthorization {
    /// Builds the payload for one unit on `lane_nonce`.
    #[must_use]
    pub fn new(channel_id: B256, epoch: u64, lane_nonce: LaneNonce) -> Self {
        Self {
            channelId: channel_id,
            epoch,
            channelNonce: lane_nonce.pack(),
        }
    }

    /// EIP-712 signing hash, the value `spendKey` signs and the escrow recovers against.
    #[must_use]
    pub fn digest(&self, domain: &Eip712Domain) -> B256 {
        self.eip712_signing_hash(domain)
    }

    /// Signs this authorisation.
    ///
    /// # Errors
    /// Returns an error if the signer fails.
    pub fn sign<S: SignerSync>(
        &self,
        signer: &S,
        domain: &Eip712Domain,
    ) -> Result<Signature, alloy::signers::Error> {
        signer.sign_hash_sync(&self.digest(domain))
    }

    /// Recovers the signer, rejecting anything the escrow's `ECDSA.recover` would reject.
    ///
    /// Rejects high-`s` signatures, a zero `r` or `s`, and zero-address recovery. The `v`
    /// byte is not checked here: [`Signature`] only holds a parity bit and re-serialises it
    /// as 27 or 28, so a non-canonical `v` cannot survive parsing into this type.
    ///
    /// # Errors
    /// See [`RecoverError`].
    pub fn recover(
        &self,
        domain: &Eip712Domain,
        signature: &Signature,
    ) -> Result<Address, RecoverError> {
        if signature.r().is_zero() || signature.s().is_zero() {
            return Err(RecoverError::ZeroComponent);
        }
        if signature.normalize_s().is_some() {
            return Err(RecoverError::HighS);
        }
        let recovered = signature
            .recover_address_from_prehash(&self.digest(domain))
            .map_err(|e| RecoverError::Failed(e.to_string()))?;
        if recovered.is_zero() {
            return Err(RecoverError::ZeroAddress);
        }
        Ok(recovered)
    }
}

/// The epoch a timestamp falls in, or `None` before `epochZero`.
///
/// `epochLength` of zero has no epochs; the escrow rejects such a channel at open.
#[must_use]
pub fn epoch_of(created_at: u64, settings: &ChannelSettings) -> Option<u64> {
    if settings.epochLength == 0 {
        return None;
    }
    created_at
        .checked_sub(settings.epochZero)
        .map(|elapsed| elapsed / settings.epochLength)
}

/// First second after `epoch` ends, or `None` if the schedule overflows `u64`.
#[must_use]
pub fn epoch_end(settings: &ChannelSettings, epoch: u64) -> Option<u64> {
    epoch
        .checked_add(1)?
        .checked_mul(settings.epochLength)?
        .checked_add(settings.epochZero)
}

#[cfg(test)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "shared test helpers for sibling modules"
)]
pub(crate) mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy_primitives::{U256, address, b256};
    use k256::ecdsa::SigningKey;

    /// Escrow address used by every test domain.
    pub(crate) const ESCROW: Address = address!("0x6666666666666666666666666666666666666666");
    /// Chain id used by every test domain.
    pub(crate) const CHAIN_ID: u64 = 480;
    /// The RP every test channel pays for.
    pub(crate) const RP_ID: u64 = 7;
    /// Seconds in a test epoch.
    pub(crate) const EPOCH_LENGTH: u64 = 3_600;
    /// Start of epoch 0 in every test channel.
    pub(crate) const EPOCH_ZERO: u64 = 1_700_000_000;

    pub(crate) fn signer(byte: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_signing_key(
            SigningKey::from_bytes(&[byte; 32].into()).expect("valid test key"),
        )
    }

    pub(crate) fn test_domain() -> Eip712Domain {
        domain(CHAIN_ID, ESCROW)
    }

    pub(crate) fn settings(spend_key: Address) -> ChannelSettings {
        ChannelSettings {
            rpId: RP_ID,
            spendKey: spend_key,
            collector: address!("0x3333333333333333333333333333333333333333"),
            token: address!("0x4444444444444444444444444444444444444444"),
            pricePerUnit: U256::from(1_000_000_000_000_000_000u128),
            epochLength: EPOCH_LENGTH,
            epochZero: EPOCH_ZERO,
            salt: b256!("0x00000000000000000000000000000000000000000000000000000000000000ff"),
        }
    }

    #[test]
    fn type_strings_are_the_spec_strings() {
        assert_eq!(
            ChannelSettings::eip712_encode_type(),
            "ChannelSettings(uint64 rpId,address spendKey,address collector,address token,uint256 pricePerUnit,uint64 epochLength,uint64 epochZero,bytes32 salt)"
        );
        assert_eq!(
            PaymentAuthorization::eip712_encode_type(),
            "PaymentAuthorization(bytes32 channelId,uint64 epoch,uint96 channelNonce)"
        );
    }

    #[test]
    fn channel_id_commits_to_chain_escrow_and_settings() {
        let s = settings(signer(1).address());
        let here = s.channel_id(&test_domain());

        assert_ne!(here, s.channel_id(&domain(1, ESCROW)), "chain id");
        assert_ne!(
            here,
            s.channel_id(&domain(
                CHAIN_ID,
                address!("0x0000000000000000000000000000000000009999")
            )),
            "escrow address"
        );

        let mut other = s.clone();
        other.salt = B256::ZERO;
        assert_ne!(here, other.channel_id(&test_domain()), "salt");

        let mut repriced = s;
        repriced.pricePerUnit = U256::from(2u64);
        assert_ne!(here, repriced.channel_id(&test_domain()), "price");
    }

    #[test]
    fn sign_then_recover_roundtrips() {
        let key = signer(1);
        let s = settings(key.address());
        let auth = PaymentAuthorization::new(s.channel_id(&test_domain()), 3, LaneNonce::new(1, 2));
        let signature = auth.sign(&key, &test_domain()).expect("signs");
        assert_eq!(
            auth.recover(&test_domain(), &signature).expect("recovers"),
            key.address()
        );
    }

    /// Every field is bound: changing any of them must break recovery.
    #[test]
    fn an_authorization_is_bound_to_one_channel_epoch_and_nonce() {
        let key = signer(1);
        let channel = settings(key.address()).channel_id(&test_domain());
        let auth = PaymentAuthorization::new(channel, 3, LaneNonce::new(1, 2));
        let signature = auth.sign(&key, &test_domain()).expect("signs");

        for altered in [
            PaymentAuthorization::new(B256::ZERO, 3, LaneNonce::new(1, 2)),
            PaymentAuthorization::new(channel, 4, LaneNonce::new(1, 2)),
            PaymentAuthorization::new(channel, 3, LaneNonce::new(1, 3)),
            PaymentAuthorization::new(channel, 3, LaneNonce::new(2, 2)),
        ] {
            assert_ne!(
                altered
                    .recover(&test_domain(), &signature)
                    .expect("recovers to something"),
                key.address()
            );
        }
    }

    #[test]
    fn recover_rejects_non_canonical_signatures() {
        let key = signer(1);
        let channel = settings(key.address()).channel_id(&test_domain());
        let auth = PaymentAuthorization::new(channel, 3, LaneNonce::new(0, 1));
        let signature = auth.sign(&key, &test_domain()).expect("signs");

        // secp256k1n - s, the malleable twin of a canonical signature.
        let order = U256::from_be_bytes(
            b256!("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").0,
        );
        let high_s = Signature::new(signature.r(), order - signature.s(), !signature.v());
        assert_eq!(
            auth.recover(&test_domain(), &high_s),
            Err(RecoverError::HighS)
        );

        let zero_r = Signature::new(U256::ZERO, signature.s(), signature.v());
        assert_eq!(
            auth.recover(&test_domain(), &zero_r),
            Err(RecoverError::ZeroComponent)
        );
        let zero_s = Signature::new(signature.r(), U256::ZERO, signature.v());
        assert_eq!(
            auth.recover(&test_domain(), &zero_s),
            Err(RecoverError::ZeroComponent)
        );
    }

    #[test]
    fn epochs_are_floor_divided_from_epoch_zero() {
        let s = settings(signer(1).address());
        assert_eq!(epoch_of(EPOCH_ZERO - 1, &s), None, "before epoch zero");
        assert_eq!(epoch_of(EPOCH_ZERO, &s), Some(0));
        assert_eq!(epoch_of(EPOCH_ZERO + EPOCH_LENGTH - 1, &s), Some(0));
        assert_eq!(epoch_of(EPOCH_ZERO + EPOCH_LENGTH, &s), Some(1));
        assert_eq!(epoch_of(EPOCH_ZERO + 5 * EPOCH_LENGTH + 7, &s), Some(5));

        assert_eq!(epoch_end(&s, 0), Some(EPOCH_ZERO + EPOCH_LENGTH));
        assert_eq!(epoch_end(&s, 4), Some(EPOCH_ZERO + 5 * EPOCH_LENGTH));
        assert_eq!(epoch_end(&s, u64::MAX), None, "no overflow");

        let mut degenerate = s;
        degenerate.epochLength = 0;
        assert_eq!(epoch_of(EPOCH_ZERO, &degenerate), None);
    }

    /// Reads the Solidity test suite's cross-language vectors.
    fn solidity_vectors() -> (Eip712Domain, ChannelSettings, serde_json::Value) {
        use std::str::FromStr as _;

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/test/vectors/fee-escrow.json"
        );
        let raw = std::fs::read_to_string(path).expect("read the vectors");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse the vectors");

        let addr = |value: &serde_json::Value| {
            Address::from_str(value.as_str().expect("address string")).expect("address")
        };
        let u64_of = |value: &serde_json::Value| value.as_u64().expect("u64");

        let vector_domain = domain(
            u64_of(&v["domain"]["chainId"]),
            addr(&v["domain"]["verifyingContract"]),
        );
        let raw_settings = &v["settings"];
        let settings = ChannelSettings {
            rpId: u64_of(&raw_settings["rpId"]),
            spendKey: addr(&raw_settings["spendKey"]),
            collector: addr(&raw_settings["collector"]),
            token: addr(&raw_settings["token"]),
            pricePerUnit: U256::from_str(
                raw_settings["pricePerUnit"].as_str().expect("price string"),
            )
            .expect("price"),
            epochLength: u64_of(&raw_settings["epochLength"]),
            epochZero: u64_of(&raw_settings["epochZero"]),
            salt: hash(&raw_settings["salt"]),
        };
        (vector_domain, settings, v)
    }

    fn hash(value: &serde_json::Value) -> B256 {
        use std::str::FromStr as _;
        B256::from_str(value.as_str().expect("hash string")).expect("hash")
    }

    /// The channel id must be the same 32 bytes in both languages.
    #[test]
    fn channel_id_matches_the_solidity_vector() {
        let (vector_domain, settings, v) = solidity_vectors();
        assert_eq!(settings.channel_id(&vector_domain), hash(&v["channelId"]));
    }

    /// The payment digest must be the same 32 bytes in both languages.
    #[test]
    fn payment_digest_matches_the_solidity_vector() {
        let (vector_domain, _settings, v) = solidity_vectors();
        let a = &v["paymentAuthorization"];
        let auth = PaymentAuthorization::new(
            hash(&a["channelId"]),
            a["epoch"].as_u64().expect("u64"),
            LaneNonce::from_hex(a["channelNonce"].as_str().expect("nonce string")).expect("nonce"),
        );
        assert_eq!(auth.digest(&vector_domain), hash(&a["digest"]));
    }

    /// The domain separator itself, pinned by the Solidity suite.
    #[test]
    fn domain_separator_matches_the_solidity_vector() {
        use alloy_primitives::b256;

        let (vector_domain, _settings, _v) = solidity_vectors();
        assert_eq!(
            vector_domain.separator(),
            b256!("0x9f429a61ffdfe791688ddf302376b5d04006d31a9bc008b9484edcd93d262408")
        );
    }
}
