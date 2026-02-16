// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ISP1Verifier} from "@optimism-bedrock/src/dispute/zk/ISP1Verifier.sol";
import {Lib} from "../Lib.sol";
import {WorldIDGateway} from "../Gateway.sol";
import {STATE_BRIDGE_STORAGE_SLOT} from "../StateBridge.sol";
import "../../Error.sol";

/// @notice Emitted when the light client state is advanced via a verified ZK proof.
event LightClientUpdated(uint256 indexed slot, bytes32 executionStateRoot);

/// @notice Emitted when a sync committee hash is written (initial set or rotation).
event SyncCommitteeUpdated(uint256 indexed period, bytes32 syncCommitteeHash);

/// @notice Emitted when the SP1 verifier address is updated.
event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

/// @notice Emitted when the Helios program verification key is updated.
event ProgramVKeyUpdated(bytes32 indexed oldVKey, bytes32 indexed newVKey);

/// @dev A (key, value) pair for a single EVM storage slot.
struct StorageSlot {
    bytes32 key;
    bytes32 value;
}

/// @dev Public values output by the SP1 Helios program. The struct includes both "prev" fields
///   (which the contract reconstructs from its own storage) and "new" fields (which the relayer
///   provides). The SP1 proof verifies against the ABI-encoded struct, binding the proof to the
///   specific on-chain state it chains from.
struct ProofOutputs {
    bytes32 prevHeader;
    uint256 prevHead;
    bytes32 prevSyncCommitteeHash;
    uint256 newHead;
    bytes32 newHeader;
    bytes32 executionStateRoot;
    uint256 executionBlockNumber;
    bytes32 syncCommitteeHash;
    bytes32 nextSyncCommitteeHash;
    StorageSlot[] storageSlots;
}

/// @title LightClientGatewayAdapter
/// @author World Contributors
/// @notice Trustless verification adapter that verifies SP1 Helios ZK proofs of Ethereum consensus
///   inline during relay. Verification pipeline:
///
///   1. Reconstruct ProofOutputs from on-chain state + relayer-provided new values
///   2. Verify SP1 proof against reconstructed public values (binds proof to on-chain state)
///   3. MPT prove L1 StateBridge's keccak chain head from the verified L1 state root
///
/// @dev Trust model:
///   - L1 consensus: ZK-proven (trustless — BLS signature verification via ZK proof)
///   - L1 StateBridge state: Proven via MPT against the ZK-verified L1 state root
///   - Chain head authenticity: The L1 StateBridge already verified WC state via DisputeGame + MPT
///     before committing the chain head, so this adapter inherits that trust transitively
///
/// @dev Light client state management:
///   The adapter maintains minimal beacon chain state for incremental proof chaining:
///   - `headers[slot]`: Beacon block header hash for each proven slot
///   - `syncCommitteeHashes[period]`: Hash of the sync committee for each period
///   - `head`: Latest verified slot
///   Each proof must chain from the current on-chain state — the contract reconstructs the
///   ProofOutputs struct with `prevHeader`, `prevHead`, and `prevSyncCommitteeHash` from its own
///   storage, ensuring continuity.
contract LightClientGatewayAdapter is WorldIDGateway, Ownable {
    using Lib for *;

    ////////////////////////////////////////////////////////////
    //                       CONSTANTS                        //
    ////////////////////////////////////////////////////////////

    /// @dev Number of slots per sync committee period (8192 slots = ~27 hours).
    uint256 internal constant SLOTS_PER_PERIOD = 8192;

    ////////////////////////////////////////////////////////////
    //                         STATE                          //
    ////////////////////////////////////////////////////////////

    /// @notice The SP1 verifier gateway contract (e.g. Succinct's SP1VerifierGateway).
    ISP1Verifier public verifier;

    /// @notice The verification key identifying the SP1 Helios program.
    bytes32 public programVKey;

    /// @notice The latest verified L1 beacon chain slot.
    uint256 public head;

    /// @notice Maps beacon slot to its proven header hash.
    mapping(uint256 => bytes32) public headers;

    /// @notice Hash of the sync committee for each period.
    mapping(uint256 => bytes32) public syncCommitteeHashes;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    /// @param owner_ The owner who can update verifier and vkey addresses.
    /// @param verifier_ The SP1 verifier gateway address.
    /// @param programVKey_ The SP1 Helios program verification key.
    /// @param initialHead_ The initial beacon chain slot (must be a checkpoint slot).
    /// @param initialHeader_ The beacon block header hash for the initial slot.
    /// @param initialSyncCommitteeHash_ The hash of the sync committee at the initial slot's period.
    /// @param bridge_ The WorldIDSatellite contract on this chain.
    /// @param l1Bridge_ The L1 StateBridge address whose chain head we prove via MPT.
    /// @param l1ChainId_ The L1 chain ID (e.g. 1 for mainnet).
    constructor(
        address owner_,
        address verifier_,
        bytes32 programVKey_,
        uint256 initialHead_,
        bytes32 initialHeader_,
        bytes32 initialSyncCommitteeHash_,
        address bridge_,
        address l1Bridge_,
        uint256 l1ChainId_
    ) WorldIDGateway(bridge_, l1Bridge_, l1ChainId_) Ownable(owner_) {
        if (verifier_ == address(0)) revert ZeroAddress();
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        head = initialHead_;
        headers[initialHead_] = initialHeader_;
        syncCommitteeHashes[initialHead_ / SLOTS_PER_PERIOD] = initialSyncCommitteeHash_;
    }

    ////////////////////////////////////////////////////////////
    //                     ERC-7786 SOURCE                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc WorldIDGateway
    function supportsAttribute(bytes4 selector) public view virtual override returns (bool) {
        return selector == ZK_GATEWAY_ATTRIBUTES;
    }

    /// @dev Verifies SP1 Helios ZK proof of L1 consensus + single-hop MPT proof to extract
    ///   the proven chain head from the L1 StateBridge.
    function _verifyAndExtract(bytes calldata, bytes[] calldata attributes)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        (bytes4 sel, bytes memory data) = split(attributes[0]);
        if (sel != ZK_GATEWAY_ATTRIBUTES) revert MissingAttribute(ZK_GATEWAY_ATTRIBUTES);

        // Decode relay parameters from attribute data
        (
            bytes memory proof,
            uint256 newHead,
            bytes32 newHeader,
            bytes32 executionStateRoot,
            uint256 executionBlockNumber,
            bytes32 syncCommitteeHash,
            bytes32 nextSyncCommitteeHash,
            bytes[] memory accountProof,
            bytes[] memory storageProof
        ) = abi.decode(data, (bytes, uint256, bytes32, bytes32, uint256, bytes32, bytes32, bytes[], bytes[]));

        // 1. Verify sync committee for current period is set
        bytes32 currentSyncCommitteeHash = syncCommitteeHashes[head / SLOTS_PER_PERIOD];
        if (currentSyncCommitteeHash == bytes32(0)) revert SyncCommitteeNotSet();

        // 2. Reconstruct ProofOutputs from on-chain prev* state + relayer-provided new* values.
        //    The proof will only verify if these match what the SP1 program committed.
        {
            ProofOutputs memory po = ProofOutputs({
                prevHeader: headers[head],
                prevHead: head,
                prevSyncCommitteeHash: currentSyncCommitteeHash,
                newHead: newHead,
                newHeader: newHeader,
                executionStateRoot: executionStateRoot,
                executionBlockNumber: executionBlockNumber,
                syncCommitteeHash: syncCommitteeHash,
                nextSyncCommitteeHash: nextSyncCommitteeHash,
                storageSlots: new StorageSlot[](0)
            });

            verifier.verifyProof(programVKey, abi.encode(po), proof);
        }

        // 3. Enforce slot monotonicity
        if (newHead <= head) revert SlotBehindHead();

        // 4. Enforce checkpoint slot (CL nodes only store checkpoint slot proofs)
        if (newHead % 32 != 0) revert NonCheckpointSlot();

        // 5. Update head and header
        head = newHead;
        headers[newHead] = newHeader;

        // 6. Handle sync committee updates
        {
            uint256 newPeriod = newHead / SLOTS_PER_PERIOD;

            // Set current period's sync committee if not already set (handles period jumps)
            if (syncCommitteeHashes[newPeriod] == bytes32(0)) {
                syncCommitteeHashes[newPeriod] = syncCommitteeHash;
                emit SyncCommitteeUpdated(newPeriod, syncCommitteeHash);
            }

            // Process next sync committee rotation if present
            if (nextSyncCommitteeHash != bytes32(0)) {
                uint256 nextPeriod = newPeriod + 1;
                bytes32 existing = syncCommitteeHashes[nextPeriod];
                if (existing == bytes32(0)) {
                    syncCommitteeHashes[nextPeriod] = nextSyncCommitteeHash;
                    emit SyncCommitteeUpdated(nextPeriod, nextSyncCommitteeHash);
                } else if (existing != nextSyncCommitteeHash) {
                    revert NextSyncCommitteeMismatch();
                }
            }
        }

        emit LightClientUpdated(newHead, executionStateRoot);

        // 7. MPT prove L1 StateBridge's keccak chain head against the verified L1 state root
        chainHead = Lib.proveStorageSlot(
            ANCHOR_BRIDGE, STATE_BRIDGE_STORAGE_SLOT, accountProof, storageProof, executionStateRoot
        );
    }

    ////////////////////////////////////////////////////////////
    //                    ADMIN FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice Updates the SP1 verifier gateway address.
    function setVerifier(address newVerifier) external virtual onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        address old = address(verifier);
        verifier = ISP1Verifier(newVerifier);
        emit VerifierUpdated(old, newVerifier);
    }

    /// @notice Updates the SP1 Helios program verification key.
    function setProgramVKey(bytes32 newVKey) external virtual onlyOwner {
        bytes32 old = programVKey;
        programVKey = newVKey;
        emit ProgramVKeyUpdated(old, newVKey);
    }

    /// @notice Sets a sync committee hash for a specific period.
    /// @dev Used for bootstrapping or correcting sync committee state.
    function setSyncCommitteeHash(uint256 period, bytes32 hash) external virtual onlyOwner {
        syncCommitteeHashes[period] = hash;
        emit SyncCommitteeUpdated(period, hash);
    }
}
