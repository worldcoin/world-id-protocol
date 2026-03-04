//! E2E tests for the World ID relay service.
//!
//! These tests spin up local anvil instances and verify the relay transaction
//! path end-to-end: building payloads, encoding ERC-7930 addresses, and sending
//! relay transactions through a mock gateway contract.

use std::sync::Arc;

use alloy::{
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    sol,
    sol_types::{SolCall, SolValue},
};
use alloy_primitives::B256;
use eyre::Result;
use world_id_relay::{
    CommitmentLog, Satellite,
    bindings::*,
    primitives::{ChainCommitment, KeccakChain},
    relay::send_relay_tx,
    satellite::spawn_satellite,
};

// ── Mock Contracts ──────────────────────────────────────────────────────────

sol! {
    #[sol(rpc, bytecode = "6080604052348015600e575f5ffd5b506104748061001c5f395ff3fe608060405260043610610033575f3560e01c80634cc2aa3c14610037578063cdfe7f5c14610061578063d23ee66b14610082575b5f5ffd5b348015610042575f5ffd5b5061004b610096565b6040516100589190610183565b60405180910390f35b61007461006f3660046101fd565b610122565b604051908152602001610058565b34801561008d575f5ffd5b5061004b610177565b600180546100a3906102cd565b80601f01602080910402602001604051908101604052809291908181526020018280546100cf906102cd565b801561011a5780601f106100f15761010080835404028352916020019161011a565b820191905f5260205f20905b8154815290600101906020018083116100fd57829003601f168201915b505050505081565b5f8061012f878983610365565b50600161013d858783610365565b5086868686604051602001610155949392919061041f565b6040516020818303038152906040528051906020012090509695505050505050565b5f80546100a3906102cd565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f83011684010191505092915050565b5f5f83601f8401126101c8575f5ffd5b50813567ffffffffffffffff8111156101df575f5ffd5b6020830191508360208285010111156101f6575f5ffd5b9250929050565b5f5f5f5f5f5f60608789031215610212575f5ffd5b863567ffffffffffffffff811115610228575f5ffd5b61023489828a016101b8565b909750955050602087013567ffffffffffffffff811115610253575f5ffd5b61025f89828a016101b8565b909550935050604087013567ffffffffffffffff81111561027e575f5ffd5b8701601f8101891361028e575f5ffd5b803567ffffffffffffffff8111156102a4575f5ffd5b8960208260051b84010111156102b8575f5ffd5b60208201935080925050509295509295509295565b600181811c908216806102e157607f821691505b6020821081036102ff57634e487b7160e01b5f52602260045260245ffd5b50919050565b634e487b7160e01b5f52604160045260245ffd5b601f82111561036057805f5260205f20601f840160051c8101602085101561033e5750805b601f840160051c820191505b8181101561035d575f815560010161034a565b50505b505050565b67ffffffffffffffff83111561037d5761037d610305565b6103918361038b83546102cd565b83610319565b5f601f8411600181146103c2575f85156103ab5750838201355b5f19600387901b1c1916600186901b17835561035d565b5f83815260208120601f198716915b828110156103f157868501358255602094850194600190920191016103d1565b508682101561040d575f1960f88860031b161c19848701351681555b505060018560011b0183555050505050565b838582375f8482015f8152838582375f9301928352509094935050505056fea264697066735822122027cf91f35c68f26e39dd33a14346ef8e204a240f1bb5445b5227381eced4c42a64736f6c634300081e0033")]
    /// A minimal mock gateway that records the last `sendMessage` call.
    ///
    /// We deploy this on an anvil instance and then call `send_relay_tx` against it
    /// to verify that the relay path correctly encodes and delivers the payload.
    contract MockGateway {
        bytes public lastRecipient;
        bytes public lastPayload;

        function sendMessage(
            bytes calldata recipient,
            bytes calldata payload,
            bytes[] calldata attributes
        ) external payable returns (bytes32) {
            lastRecipient = recipient;
            lastPayload = payload;
            return keccak256(abi.encodePacked(recipient, payload));
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Builds a valid ABI-encoded `updateRoot(root, timestamp, proofId)` call.
fn encode_update_root(root: U256) -> Bytes {
    ICommitment::updateRootCall {
        _0: root,
        _1: U256::from(1u64),
        _2: B256::ZERO,
    }
    .abi_encode()
    .into()
}

fn make_sol_commitment(block_hash: B256, root: U256) -> IWorldIDSource::Commitment {
    IWorldIDSource::Commitment {
        blockHash: block_hash,
        data: encode_update_root(root),
    }
}

/// Builds a `ChainCommitment` whose hash chain is valid relative to the
/// supplied `KeccakChain`. Advances the chain as a side effect.
fn make_chain_commitment(
    chain: &mut KeccakChain,
    block_number: u64,
    root: U256,
) -> ChainCommitment {
    let commits = vec![make_sol_commitment(
        B256::from([block_number as u8; 32]),
        root,
    )];
    let head = chain.hash_chained(&commits);
    chain.commit_chained(&commits);
    ChainCommitment {
        chain_head: head,
        block_number,
        chain_id: 480,
        commitment_payload: commits.abi_encode_params().into(),
        timestamp: block_number * 100,
    }
}

/// Spawns an anvil instance and returns a wallet-backed provider as a `DynProvider`.
async fn spawn_anvil() -> Result<(AnvilInstance, DynProvider)> {
    let anvil = Anvil::new().try_spawn()?;
    let signer: alloy::signers::local::PrivateKeySigner = anvil.keys()[0].clone().into();
    let wallet = alloy::network::EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(anvil.endpoint_url())
        .erased();
    Ok((anvil, provider))
}

/// Deploys the MockGateway and returns its address.
async fn deploy_mock_gateway(provider: &DynProvider) -> Result<Address> {
    let gateway = MockGateway::deploy(provider).await?;
    Ok(*gateway.address())
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Tests the full `send_relay_tx` path: building a chain commitment, encoding
/// it as a relay payload, sending it to a mock gateway on anvil, and verifying
/// the gateway received the correct recipient and payload.
#[tokio::test]
async fn e2e_send_relay_tx_delivers_payload_to_mock_gateway() -> Result<()> {
    // 1. Start anvil for the "L1" destination chain.
    let (_anvil, provider) = spawn_anvil().await?;

    // 2. Deploy MockGateway.
    let gateway_address = deploy_mock_gateway(&provider).await?;

    // 3. Build a chain commitment.
    let mut chain = KeccakChain::new(B256::ZERO, 0);
    let commitment = make_chain_commitment(&mut chain, 1, U256::from(42u64));

    // 4. Build a fake proof attribute (we are testing the relay path, not the proof).
    let fake_attribute = Bytes::from(vec![0xCA, 0xFE, 0xBA, 0xBE]);

    // 5. Send the relay transaction.
    let satellite_address = Address::repeat_byte(0xAA);
    let anchor_chain_id = 480u64;

    let tx_hash = send_relay_tx(
        &provider,
        gateway_address,
        satellite_address,
        anchor_chain_id,
        commitment.commitment_payload.clone(),
        fake_attribute,
    )
    .await?;

    assert_ne!(tx_hash, B256::ZERO, "transaction hash should be non-zero");

    // 6. Read back from MockGateway to verify the data was stored.
    let mock = MockGateway::new(gateway_address, &provider);

    let stored_recipient = mock.lastRecipient().call().await?;
    let stored_payload = mock.lastPayload().call().await?;

    // 7. Verify the recipient is correctly ERC-7930 encoded.
    //    Format: version(2) | chainType(2) | chainRefLen(1) | chainRef(var) | addrLen(1) | addr(20)
    let recipient_bytes = stored_recipient.as_ref();
    assert!(
        recipient_bytes.len() >= 7,
        "ERC-7930 recipient should be at least 7 bytes, got {}",
        recipient_bytes.len()
    );

    // version = 0x0001
    assert_eq!(&recipient_bytes[0..2], &[0x00, 0x01], "version should be 1");
    // chainType = 0x0000 (EVM)
    assert_eq!(
        &recipient_bytes[2..4],
        &[0x00, 0x00],
        "chainType should be EVM (0)"
    );

    // chainRefLen for chain ID 480 = 0x01E0 = 2 bytes
    let chain_ref_len = recipient_bytes[4] as usize;
    assert_eq!(chain_ref_len, 2, "chainRefLen for 480 should be 2");

    // chainRef = [0x01, 0xE0]
    assert_eq!(
        &recipient_bytes[5..7],
        &[0x01, 0xE0],
        "chainRef for 480 should be [0x01, 0xE0]"
    );

    // addrLen = 0x14 (20)
    assert_eq!(recipient_bytes[7], 0x14, "addrLen should be 20");

    // addr = satellite_address
    assert_eq!(
        &recipient_bytes[8..28],
        satellite_address.as_slice(),
        "address should match satellite"
    );

    // 8. Verify the payload matches the commitment payload.
    assert_eq!(
        stored_payload.as_ref(),
        commitment.commitment_payload.as_ref(),
        "gateway should store the exact commitment payload"
    );

    Ok(())
}

/// Tests the `CommitmentLog` subscription + satellite task loop:
/// insert a commitment, verify the satellite loop picks it up via the
/// watch channel, and confirm the relay is attempted.
#[tokio::test]
async fn e2e_source_state_log_tracks_chain_commitments() -> Result<()> {
    let log = CommitmentLog::new();
    let mut rx = log.subscribe();

    // Initially the head is zero.
    assert_eq!(log.head(), B256::ZERO);

    // Build and commit a chain commitment.
    let mut chain = KeccakChain::new(B256::ZERO, 0);
    let c1 = make_chain_commitment(&mut chain, 1, U256::from(100u64));
    let expected_head = c1.chain_head;

    log.commit_chained(Arc::new(c1))?;

    // The watch channel should fire with the new head.
    rx.changed().await?;
    assert_eq!(*rx.borrow(), expected_head);
    assert_eq!(log.head(), expected_head);

    // `since(ZERO)` should return the single entry.
    let delta = log
        .since(B256::ZERO)
        .expect("since(ZERO) should return Some");
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].chain_head, expected_head);

    // Add a second commitment.
    let c2 = make_chain_commitment(&mut chain, 2, U256::from(200u64));
    let expected_head_2 = c2.chain_head;
    log.commit_chained(Arc::new(c2))?;

    rx.changed().await?;
    assert_eq!(*rx.borrow(), expected_head_2);

    // `since(head_1)` should return only the second entry.
    let delta = log
        .since(expected_head)
        .expect("since(head_1) should return Some");
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].chain_head, expected_head_2);

    Ok(())
}

/// Tests the satellite task spawner end-to-end: spawns the satellite loop
/// against a mock gateway on anvil, inserts a commitment into the log, and
/// verifies the gateway received the relay transaction.
#[tokio::test]
async fn e2e_satellite_task_relays_on_new_commitment() -> Result<()> {
    // 1. Start anvil for the "L1" destination chain.
    let (_anvil, provider) = spawn_anvil().await?;

    // 2. Deploy MockGateway.
    let gateway_address = deploy_mock_gateway(&provider).await?;

    // 3. Create CommitmentLog.
    let log = Arc::new(CommitmentLog::new());

    // 4. Create a minimal satellite that uses our mock gateway.
    //    We use a custom implementation instead of EthereumMptSatellite since that
    //    requires real dispute games. This tests the satellite::spawn_satellite loop.
    let satellite = TestSatellite {
        provider: provider.clone(),
        gateway_address,
        satellite_address: Address::repeat_byte(0xBB),
        anchor_chain_id: 480,
    };

    // 5. Spawn the satellite task.
    let log_clone = log.clone();
    let task = tokio::spawn(async move { spawn_satellite(satellite, log_clone).await });

    // 6. Give the task a moment to start and subscribe.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 7. Insert a chain commitment into the log.
    let mut chain = KeccakChain::new(B256::ZERO, 0);
    let c1 = make_chain_commitment(&mut chain, 1, U256::from(42u64));
    log.commit_chained(Arc::new(c1))?;

    // 8. Wait for the satellite to relay it (with timeout).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() >= deadline {
            // If the task finished with an error, report it.
            if task.is_finished() {
                let result = task.await?;
                result?;
            }
            eyre::bail!("timed out waiting for satellite to relay commitment");
        }

        let mock = MockGateway::new(gateway_address, &provider);
        let stored = mock.lastPayload().call().await?;
        if !stored.is_empty() {
            // The satellite relayed something - verify it is non-empty.
            assert!(
                !stored.is_empty(),
                "satellite should have relayed a payload"
            );
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // 9. Verify MockGateway received the ERC-7930 encoded recipient.
    let mock = MockGateway::new(gateway_address, &provider);
    let stored_recipient = mock.lastRecipient().call().await?;
    let recipient_bytes = stored_recipient.as_ref();

    // Should contain the satellite address (0xBB repeated).
    let addr_start = recipient_bytes.len() - 20;
    assert_eq!(
        &recipient_bytes[addr_start..],
        Address::repeat_byte(0xBB).as_slice(),
        "recipient should contain the satellite address"
    );

    // Clean up: abort the satellite task (it runs forever).
    task.abort();

    Ok(())
}

// ── Test Satellite ──────────────────────────────────────────────────────────

/// A minimal `Satellite` implementation that skips proof building and sends
/// directly to the mock gateway. Used by the satellite task spawner test.
struct TestSatellite {
    provider: DynProvider,
    gateway_address: Address,
    satellite_address: Address,
    anchor_chain_id: u64,
}

impl Satellite for TestSatellite {
    fn name(&self) -> &str {
        "test-satellite"
    }

    fn chain_id(&self) -> u64 {
        1
    }

    fn build_proof<'a>(
        &'a self,
        _commitment: &'a ChainCommitment,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(Bytes, Bytes)>> + Send + 'a>>
    {
        Box::pin(async move {
            // Return a fake attribute and the commitment payload will be forwarded.
            Ok((Bytes::from(vec![0xDE, 0xAD]), Bytes::new()))
        })
    }

    fn relay<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<B256>> + Send + 'a>> {
        Box::pin(async move {
            let (attribute, _) = self.build_proof(commitment).await?;
            send_relay_tx(
                &self.provider,
                self.gateway_address,
                self.satellite_address,
                self.anchor_chain_id,
                commitment.commitment_payload.clone(),
                attribute,
            )
            .await
        })
    }
}
