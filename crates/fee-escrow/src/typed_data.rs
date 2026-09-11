//! EIP-712 typed data for the `WorldIDFeeEscrow` contract.
//!
//! Mirrors `contracts/src/core/WorldIDFeeEscrow.sol`. The type strings here must stay
//! byte-identical to `OPEN_CHANNEL_TYPEHASH` and `PAYMENT_AUTHORIZATION_TYPEHASH`.

use alloy::{
    signers::{Signature, SignerSync},
    sol_types::{Eip712Domain, SolStruct as _, eip712_domain},
};
use alloy_primitives::{Address, B256, U256, keccak256};

/// These structs live in a private module so the EIP-712 payloads are not mistaken for
/// contract call bindings. They are only used for hashing, signing, and recovery.
mod sol_types {
    use alloy::sol;

    sol! {
        /// Immutable channel terms, `IWorldIDFeeEscrow.ChannelSettings`.
        ///
        /// Field order is load-bearing: it fixes both the `OpenChannel` type string and the
        /// ABI encoding used by [`super::channel_id`].
        #[derive(Debug)]
        struct ChannelSettings {
            uint64 rpId;
            address payer;
            address spendKey;
            address collector;
            address token;
            address feeSchedule;
            uint32 laneCount;
            uint64 collectionDeadline;
            bytes32 salt;
        }

        /// EIP-712 payload the RP signs to consent to a channel being opened on its `rpId`.
        ///
        /// Flattened copy of `ChannelSettings`; the contract hashes the members inline
        /// rather than as a nested struct.
        #[derive(Debug)]
        struct OpenChannel {
            uint64 rpId;
            address payer;
            address spendKey;
            address collector;
            address token;
            address feeSchedule;
            uint32 laneCount;
            uint64 collectionDeadline;
            bytes32 salt;
        }

        /// EIP-712 payload the RP's `spendKey` signs to authorise one unit of paid work.
        #[derive(Debug)]
        struct PaymentAuthorization {
            bytes32 channelId;
            uint64 rpId;
            uint96 channelNonce;
            bytes32 rpRequestDigest;
        }
    }
}

/// Immutable channel terms, `IWorldIDFeeEscrow.ChannelSettings`.
pub type ChannelSettings = sol_types::ChannelSettings;
/// EIP-712 typed-data payload for `openChannel`.
pub type OpenChannelTypedData = sol_types::OpenChannel;
/// EIP-712 typed-data payload for a single payment authorisation.
pub type PaymentAuthorizationTypedData = sol_types::PaymentAuthorization;

/// EIP-712 domain of the escrow at `escrow` on `chain_id`.
#[must_use]
pub const fn domain(chain_id: u64, escrow: Address) -> Eip712Domain {
    eip712_domain!(
        name: "WorldIDFeeEscrow",
        version: "1.0",
        chain_id: chain_id,
        verifying_contract: escrow,
    )
}

/// Computes `keccak256(abi.encode(chainId, escrow, settings))`, matching `computeChannelId`.
#[must_use]
pub fn channel_id(chain_id: u64, escrow: Address, settings: &ChannelSettings) -> B256 {
    use alloy::sol_types::SolValue as _;

    keccak256((U256::from(chain_id), escrow, settings.clone()).abi_encode())
}

/// Signs the `OpenChannel` payload for `settings`.
///
/// # Errors
/// Returns an error if the signer fails to sign the digest.
pub fn sign_open_channel<S: SignerSync>(
    signer: &S,
    settings: &ChannelSettings,
    domain: &Eip712Domain,
) -> Result<Signature, alloy::signers::Error> {
    let payload = OpenChannelTypedData {
        rpId: settings.rpId,
        payer: settings.payer,
        spendKey: settings.spendKey,
        collector: settings.collector,
        token: settings.token,
        feeSchedule: settings.feeSchedule,
        laneCount: settings.laneCount,
        collectionDeadline: settings.collectionDeadline,
        salt: settings.salt,
    };
    signer.sign_hash_sync(&payload.eip712_signing_hash(domain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn settings() -> ChannelSettings {
        ChannelSettings {
            rpId: 7,
            payer: address!("0x1111111111111111111111111111111111111111"),
            spendKey: address!("0x2222222222222222222222222222222222222222"),
            collector: address!("0x3333333333333333333333333333333333333333"),
            token: address!("0x4444444444444444444444444444444444444444"),
            feeSchedule: address!("0x5555555555555555555555555555555555555555"),
            laneCount: 2,
            collectionDeadline: 1_800_000_000,
            salt: b256!("0x00000000000000000000000000000000000000000000000000000000000000ff"),
        }
    }

    /// Pins the exact word layout Solidity's `abi.encode(chainid, address(this), settings)`
    /// produces: two leading words then the nine static members inline, no offset word.
    #[test]
    fn channel_id_matches_solidity_abi_encoding() {
        use alloy::sol_types::SolValue as _;

        let escrow = address!("0x6666666666666666666666666666666666666666");
        let s = settings();

        let mut expected = Vec::new();
        let mut word = |bytes: [u8; 32]| expected.extend_from_slice(&bytes);
        word(U256::from(480u64).to_be_bytes());
        word(U256::from_be_slice(escrow.as_slice()).to_be_bytes());
        word(U256::from(s.rpId).to_be_bytes());
        word(U256::from_be_slice(s.payer.as_slice()).to_be_bytes());
        word(U256::from_be_slice(s.spendKey.as_slice()).to_be_bytes());
        word(U256::from_be_slice(s.collector.as_slice()).to_be_bytes());
        word(U256::from_be_slice(s.token.as_slice()).to_be_bytes());
        word(U256::from_be_slice(s.feeSchedule.as_slice()).to_be_bytes());
        word(U256::from(s.laneCount).to_be_bytes());
        word(U256::from(s.collectionDeadline).to_be_bytes());
        word(s.salt.0);

        let encoded = (U256::from(480u64), escrow, s.clone()).abi_encode();
        assert_eq!(encoded, expected, "abi encoding must be inline and static");
        assert_eq!(channel_id(480, escrow, &s), keccak256(expected));
    }

    #[test]
    fn channel_id_is_domain_separated() {
        let escrow = address!("0x6666666666666666666666666666666666666666");
        let other = address!("0x7777777777777777777777777777777777777777");
        let s = settings();

        assert_ne!(channel_id(480, escrow, &s), channel_id(1, escrow, &s));
        assert_ne!(channel_id(480, escrow, &s), channel_id(480, other, &s));

        let mut renamed = s.clone();
        renamed.salt = B256::ZERO;
        assert_ne!(
            channel_id(480, escrow, &s),
            channel_id(480, escrow, &renamed)
        );
    }

    /// The escrow's `OPEN_CHANNEL_TYPEHASH` / `PAYMENT_AUTHORIZATION_TYPEHASH` strings.
    #[test]
    fn type_strings_match_the_contract() {
        assert_eq!(
            OpenChannelTypedData::eip712_encode_type(),
            "OpenChannel(uint64 rpId,address payer,address spendKey,address collector,address token,address feeSchedule,uint32 laneCount,uint64 collectionDeadline,bytes32 salt)"
        );
        assert_eq!(
            PaymentAuthorizationTypedData::eip712_encode_type(),
            "PaymentAuthorization(bytes32 channelId,uint64 rpId,uint96 channelNonce,bytes32 rpRequestDigest)"
        );
    }
}
