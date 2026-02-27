use alloy::{
    primitives::{Address, Bytes},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use eyre::Result;
use tracing::info;

use crate::bindings::IGateway;

/// Sends a relay transaction to a gateway contract.
///
/// The gateway will verify the proof attributes and forward the payload
/// to the satellite's `receiveMessage`.
pub async fn send_relay_tx(
    provider: &DynProvider,
    gateway_address: Address,
    satellite_address: Address,
    anchor_chain_id: u64,
    payload: Bytes,
    attribute: Bytes,
) -> Result<alloy_primitives::B256> {
    // Encode satellite as ERC-7930 EVM v1 interoperable address:
    //   version(2 bytes) = 0x0001
    //   chainType(2 bytes) = 0x0001 (EVM)
    //   chainRefLen(1 byte) = variable
    //   chainRef(var bytes) = chain ID big-endian trimmed
    //   addrLen(1 byte) = 0x14 (20 bytes)
    //   addr(20 bytes) = satellite address
    let recipient = encode_evm_v1_address(anchor_chain_id, satellite_address);

    let attributes = vec![attribute];

    let call = IGateway::sendMessageCall {
        recipient: recipient.into(),
        payload,
        attributes,
    };

    let tx = TransactionRequest::default()
        .to(gateway_address)
        .input(call.abi_encode().into());

    let pending = provider.send_transaction(tx).await?;
    let tx_hash = *pending.tx_hash();

    info!(%tx_hash, %gateway_address, "relay transaction sent");

    let receipt = pending.get_receipt().await?;

    if !receipt.status() {
        eyre::bail!("relay transaction reverted: {tx_hash}");
    }

    info!(%tx_hash, "relay transaction confirmed");
    Ok(tx_hash)
}

/// Encodes an address as an ERC-7930 EVM v1 interoperable address.
///
/// Format: `version(2) | chainType(2) | chainRefLen(1) | chainRef(var) | addrLen(1) | addr(20)`
fn encode_evm_v1_address(chain_id: u64, address: Address) -> Vec<u8> {
    // Trim leading zeros from chain ID big-endian representation.
    let chain_id_bytes = chain_id.to_be_bytes();
    let first_nonzero = chain_id_bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let chain_ref = &chain_id_bytes[first_nonzero..];

    let mut buf = Vec::with_capacity(2 + 2 + 1 + chain_ref.len() + 1 + 20);
    buf.extend_from_slice(&[0x00, 0x01]); // version = 1
    buf.extend_from_slice(&[0x00, 0x01]); // chainType = 1 (EVM)
    buf.push(chain_ref.len() as u8); // chainRefLen
    buf.extend_from_slice(chain_ref); // chainRef
    buf.push(0x14); // addrLen = 20
    buf.extend_from_slice(address.as_slice()); // addr
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn encode_evm_v1_address_mainnet() {
        // Chain ID 1 (Ethereum mainnet)
        let addr = address!("1234567890abcdef1234567890abcdef12345678");
        let encoded = encode_evm_v1_address(1, addr);

        assert_eq!(encoded[0..2], [0x00, 0x01]); // version
        assert_eq!(encoded[2..4], [0x00, 0x01]); // chainType
        assert_eq!(encoded[4], 0x01); // chainRefLen = 1
        assert_eq!(encoded[5], 0x01); // chainRef = [1]
        assert_eq!(encoded[6], 0x14); // addrLen = 20
        assert_eq!(&encoded[7..27], addr.as_slice());
    }

    #[test]
    fn encode_evm_v1_address_world_chain() {
        // Chain ID 480 (World Chain)
        let addr = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let encoded = encode_evm_v1_address(480, addr);

        assert_eq!(encoded[0..2], [0x00, 0x01]); // version
        assert_eq!(encoded[2..4], [0x00, 0x01]); // chainType
        assert_eq!(encoded[4], 0x02); // chainRefLen = 2 (480 = 0x01E0)
        assert_eq!(&encoded[5..7], &[0x01, 0xE0]); // chainRef
        assert_eq!(encoded[7], 0x14); // addrLen
        assert_eq!(&encoded[8..28], addr.as_slice());
    }
}
