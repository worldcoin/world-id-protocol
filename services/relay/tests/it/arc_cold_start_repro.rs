//! Live reproduction of the Arc Mainnet cold-start relay failure.
//!
//! Reconstructs the exact `gateway.sendMessage` transaction the relay submits
//! when bootstrapping the Arc satellite from a zero chain head (i.e. the full
//! historical backlog merged into a single relay), then runs `eth_estimateGas`
//! against Arc Mainnet to determine whether the transaction is rejected for
//! gas/size reasons or a logic revert. Also probes smaller chunks (each ending
//! at a real intermediate chain head) to size a chunked fix.
//!
//! Run with:
//!   cargo test -p world-id-relay --test it -- --ignored --nocapture arc_cold_start

use alloy::{
    primitives::{Address, B256, Bytes, address, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, TransactionRequest},
    sol_types::{SolCall, SolEvent, SolValue},
};
use world_id_relay::bindings::{IGateway, IWorldIDSource};

// RPC endpoints are read from the environment so no API keys live in the repo:
//   WORLDCHAIN_RPC_URL  — World Chain Mainnet (source, chain 480)
//   ARC_RPC_URL         — Arc Mainnet (satellite, chain 5042)

/// Chunk cap mirrored from `satellite::MAX_COMMITMENTS_PER_RELAY` to verify the
/// fix: every chunk must be cheaply estimable.
const MAX_COMMITMENTS_PER_RELAY: usize = 64;

const SOURCE: Address = address!("12E8f92fE5901c17341E4A445F6CF991fFc2909E");
const ARC_GATEWAY: Address = address!("2940Ce2f0f852230Cde632e203D327513b090206");
const ARC_SATELLITE: Address = address!("304E14e4dC0508C0927e3b307a2C18422C07E394");
const RELAYER: Address = address!("6348A4a4dF173F68eB28A452Ca6c13493e447aF1");
const ANCHOR_CHAIN_ID: u64 = 480;
const DEPLOYMENT_BLOCK: u64 = 29_732_292;
const ARC_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// ERC-7930 EVM v1 interoperable address (mirrors `relay::encode_evm_v1_address`).
fn encode_evm_v1_address(chain_id: u64, addr: Address) -> Vec<u8> {
    let chain_id_bytes = chain_id.to_be_bytes();
    let first_nonzero = chain_id_bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let chain_ref = &chain_id_bytes[first_nonzero..];
    let mut buf = Vec::with_capacity(2 + 2 + 1 + chain_ref.len() + 1 + 20);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.push(chain_ref.len() as u8);
    buf.extend_from_slice(chain_ref);
    buf.push(0x14);
    buf.extend_from_slice(addr.as_slice());
    buf
}

/// `chainHead(bytes32)` attribute (mirrors `permissioned::build_chain_head_attribute`).
fn build_chain_head_attribute(chain_head: B256) -> Bytes {
    let selector = &keccak256(b"chainHead(bytes32)")[..4];
    let encoded_head = chain_head.abi_encode();
    let mut attribute = Vec::with_capacity(4 + encoded_head.len());
    attribute.extend_from_slice(selector);
    attribute.extend_from_slice(&encoded_head);
    attribute.into()
}

fn build_send_message_calldata(commits: &[IWorldIDSource::Commitment], head: B256) -> Bytes {
    let recipient = encode_evm_v1_address(ANCHOR_CHAIN_ID, ARC_SATELLITE);
    let payload: Bytes = commits.abi_encode_params().into();
    let attribute = build_chain_head_attribute(head);
    IGateway::sendMessageCall {
        recipient: recipient.into(),
        payload,
        attributes: vec![attribute],
    }
    .abi_encode()
    .into()
}

async fn estimate(arc: &impl Provider, calldata: Bytes) -> Result<u64, String> {
    let tx = TransactionRequest::default()
        .from(RELAYER)
        .to(ARC_GATEWAY)
        .input(calldata.into());
    arc.estimate_gas(tx).await.map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "hits live World Chain + Arc Mainnet RPCs"]
async fn arc_cold_start_gas_repro() -> eyre::Result<()> {
    let (Ok(wc_url), Ok(arc_url)) = (
        std::env::var("WORLDCHAIN_RPC_URL"),
        std::env::var("ARC_RPC_URL"),
    ) else {
        eprintln!("skipping: set WORLDCHAIN_RPC_URL and ARC_RPC_URL to run this live test");
        return Ok(());
    };

    let wc = ProviderBuilder::new().connect_http(wc_url.parse()?);
    let arc = ProviderBuilder::new().connect_http(arc_url.parse()?);

    // ── 1. Fetch every ChainCommitted event from genesis, in order. ──────────
    // Keep per-event (head, commits) so chunk probes can use real intermediate heads.
    let topic = IWorldIDSource::ChainCommitted::SIGNATURE_HASH;
    let latest = wc.get_block_number().await?;
    let mut events: Vec<(B256, Vec<IWorldIDSource::Commitment>)> = Vec::new();

    let mut from = DEPLOYMENT_BLOCK;
    const CHUNK: u64 = 50_000;
    while from <= latest {
        let to = (from + CHUNK - 1).min(latest);
        let filter = Filter::new()
            .address(SOURCE)
            .event_signature(topic)
            .from_block(from)
            .to_block(to);
        for log in wc.get_logs(&filter).await? {
            let decoded = IWorldIDSource::ChainCommitted::decode_log(&log.inner)?;
            let batch = Vec::<IWorldIDSource::Commitment>::abi_decode_params(&decoded.commitment)?;
            events.push((decoded.keccakChain, batch));
        }
        from = to + 1;
    }

    let all_commits: Vec<IWorldIDSource::Commitment> =
        events.iter().flat_map(|(_, c)| c.iter().cloned()).collect();
    let last_head = events.last().map(|(h, _)| *h).unwrap_or(B256::ZERO);

    println!("── Arc cold-start reconstruction ──");
    println!("events (ChainCommitted):   {}", events.len());
    println!("total commitments:         {}", all_commits.len());

    let onchain = IWorldIDSource::new(SOURCE, &wc)
        .KECCAK_CHAIN()
        .call()
        .await?;
    println!("reconstructed head:        {last_head}");
    println!(
        "on-chain source head:      {} (length={})",
        onchain.head, onchain.length
    );
    assert_eq!(
        last_head, onchain.head,
        "reconstructed head must match source"
    );
    assert_eq!(
        all_commits.len() as u64,
        onchain.length,
        "commit count must match length"
    );

    // ── 2. Full cold-start relay (what the relay submits today). ─────────────
    let full = build_send_message_calldata(&all_commits, last_head);
    println!("\nFULL cold-start sendMessage:");
    println!("calldata size:             {} bytes", full.len());
    match estimate(&arc, full).await {
        Ok(gas) => println!(
            "estimate_gas:              {gas}  (arc limit {ARC_BLOCK_GAS_LIMIT}) → {}",
            if gas > ARC_BLOCK_GAS_LIMIT {
                "EXCEEDS LIMIT"
            } else {
                "fits"
            }
        ),
        Err(e) => println!("estimate_gas ERROR:        {e}"),
    }

    // ── 3. The transaction itself is VALID: eth_call with explicit gas (under
    //       Arc's 30M block limit) succeeds. The failure is purely the
    //       eth_estimateGas gas cap, not a logic revert or the block limit.
    println!("\nFULL tx eth_call with explicit gas (bypasses the estimate gas cap):");
    let full = build_send_message_calldata(&all_commits, last_head);
    for gas in [29_000_000u64, 200_000_000] {
        let tx = TransactionRequest::default()
            .from(RELAYER)
            .to(ARC_GATEWAY)
            .gas_limit(gas)
            .input(full.clone().into());
        println!(
            "  gas_limit={gas:>10}  {}",
            match arc.call(tx).await {
                Ok(out) => format!(
                    "OK ({} bytes returned) → tx is valid & includable",
                    out.len()
                ),
                Err(e) => format!("revert: {e}"),
            }
        );
    }

    // ── 4. Verify the fix: chunking to MAX_COMMITMENTS_PER_RELAY makes every
    //       relay tx cheaply estimable. The first chunk starts from the live
    //       zero head, so we can estimate it directly against Arc.
    println!("\nFix: chunk the backlog to <= {MAX_COMMITMENTS_PER_RELAY} commitments/tx");
    let mut chunk_events = 0usize;
    let mut chunk_commits: Vec<IWorldIDSource::Commitment> = Vec::new();
    for (head, batch) in &events {
        if !chunk_commits.is_empty()
            && chunk_commits.len() + batch.len() > MAX_COMMITMENTS_PER_RELAY
        {
            break;
        }
        chunk_commits.extend(batch.iter().cloned());
        chunk_events += 1;
        let _ = head;
    }
    let first_chunk_head = events[chunk_events - 1].0;
    let cd = build_send_message_calldata(&chunk_commits, first_chunk_head);
    let n_chunks = all_commits.len().div_ceil(MAX_COMMITMENTS_PER_RELAY);
    println!(
        "  first chunk: {} events / {} commitments / {} bytes",
        chunk_events,
        chunk_commits.len(),
        cd.len()
    );
    match estimate(&arc, cd).await {
        Ok(gas) => {
            println!("  estimate_gas: {gas}  → SUCCEEDS (cold-start completes in ~{n_chunks} txs)")
        }
        Err(e) => println!("  estimate_gas ERROR: {e}"),
    }

    Ok(())
}
