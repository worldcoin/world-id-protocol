// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ISP1Verifier} from "@optimism-bedrock/src/dispute/zk/ISP1Verifier.sol";
import {ProofsLib} from "../lib/ProofsLib.sol";
import {Gateway} from "./Gateway.sol";
import {Attributes} from "./Attributes.sol";
import "../Error.sol";

/// @notice Emitted when the light client state is advanced via a verified ZK proof.
event LightClientUpdated(uint256 indexed slot, bytes32 executionStateRoot);

/// @notice Emitted when a sync committee rotation is processed.
event SyncCommitteeRotated(uint256 indexed period, bytes32 newSyncCommitteePoseidon);

/// @notice Emitted when the SP1 verifier address is updated.
event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

/// @notice Emitted when the Helios program verification key is updated.
event ProgramVKeyUpdated(bytes32 indexed oldVKey, bytes32 indexed newVKey);

/// @dev Public values output by the SP1 Helios program. The SP1 program proves that a sync
///   committee (identified by `syncCommitteePoseidon`) signed a beacon block header at `newSlot`,
///   and that header contains `executionStateRoot` in its execution payload.
struct HeliosProofOutputs {
    /// @dev The execution-layer state root at `newSlot`. This is the L1 state root used for MPT proofs.
    bytes32 executionStateRoot;
    /// @dev The new beacon chain slot that was proven.
    uint256 newSlot;
    /// @dev Poseidon hash of the sync committee that signed this block.
    bytes32 syncCommitteePoseidon;
    /// @dev Poseidon hash of the next sync committee (if rotation), or bytes32(0) if no rotation.
    bytes32 nextSyncCommitteePoseidon;
}

/// @title ZKGateway
/// @author World Contributors
/// @notice Trustless ERC-7786 gateway that verifies ZK proofs of Ethereum consensus inline during relay.
///   The SP1 Helios ZK proof proves BLS aggregate signature verification over a sync committee
///   attestation, producing a verified L1 execution state root. A single-hop MPT proof then
///   authenticates the chain head from the L1 StateBridge:
///
///   1. Verify SP1 proof → extract L1 execution state root
///   2. MPT prove L1 StateBridge's keccak chain head from L1 state root
///   3. Deliver to destination bridge via ERC-7786
///
/// @dev Trust model:
///   - L1 consensus: ZK-proven (trustless — BLS signature verification via ZK proof)
///   - L1 StateBridge state: Proven via MPT against the ZK-verified L1 state root
///   - Chain head authenticity: The L1 StateBridge already verified WC state via DisputeGame + MPT
///     before committing the chain head, so the ZKGateway inherits that trust transitively
///
/// @dev Light client state management:
///   The gateway maintains minimal sync committee state for incremental proof chaining:
///   - `syncCommitteePoseidons[period]`: Poseidon hash of the sync committee for each period
///   - `head`: Latest verified slot
///   Each proof must reference the current sync committee to be accepted. Sync committee
///   rotations are processed automatically when a proof includes a non-zero next committee.
contract ZKGateway is Gateway, Ownable {
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

    /// @notice Poseidon hash of the sync committee for each period.
    mapping(uint256 => bytes32) public syncCommitteePoseidons;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    /// @param owner_ The owner who can update verifier and vkey addresses.
    /// @param verifier_ The SP1 verifier gateway address.
    /// @param programVKey_ The SP1 Helios program verification key.
    /// @param initialSyncCommitteePeriod_ The initial sync committee period.
    /// @param initialSyncCommitteePoseidon_ The Poseidon hash of the initial sync committee.
    /// @param bridge_ The CrossDomainWorldID contract on this chain.
    /// @param l1Bridge_ The L1 StateBridge (CrossDomainWorldID) address whose chain head we prove via MPT.
    /// @param l1ChainId_ The L1 chain ID (e.g. 1 for mainnet).
    constructor(
        address owner_,
        address verifier_,
        bytes32 programVKey_,
        uint256 initialSyncCommitteePeriod_,
        bytes32 initialSyncCommitteePoseidon_,
        address bridge_,
        address l1Bridge_,
        uint256 l1ChainId_
    ) Gateway(bridge_, l1Bridge_, l1ChainId_) Ownable(owner_) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        syncCommitteePoseidons[initialSyncCommitteePeriod_] = initialSyncCommitteePoseidon_;
    }

    ////////////////////////////////////////////////////////////
    //                     ERC-7786 SOURCE                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc Gateway
    function supportsAttribute(bytes4 selector) external view virtual override returns (bool) {
        return selector == Attributes.ZK_GATEWAY_ATTRIBUTES;
    }

    /// @dev Verifies ZK proof of L1 consensus + single-hop MPT proof to extract the proven chain head
    ///   from the L1 StateBridge.
    function _verifyAndExtract(bytes calldata, bytes[] calldata attributes)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        (bytes4 selector, bytes memory data) = Attributes.split(attributes[0]);

        if (selector != Attributes.ZK_GATEWAY_ATTRIBUTES) revert MissingAttribute(Attributes.ZK_GATEWAY_ATTRIBUTES);

        (bytes memory proof, bytes memory publicValues, bytes[] memory accountProof, bytes[] memory storageProof) =
            abi.decode(data, (bytes, bytes, bytes[], bytes[]));

        verifier.verifyProof(programVKey, publicValues, proof);

        HeliosProofOutputs memory outputs = abi.decode(publicValues, (HeliosProofOutputs));

        uint256 period = outputs.newSlot / SLOTS_PER_PERIOD;
        if (syncCommitteePoseidons[period] != outputs.syncCommitteePoseidon) {
            revert InvalidSyncCommitteeRoot();
        }

        if (outputs.nextSyncCommitteePoseidon != bytes32(0)) {
            syncCommitteePoseidons[period + 1] = outputs.nextSyncCommitteePoseidon;
            emit SyncCommitteeRotated(period + 1, outputs.nextSyncCommitteePoseidon);
        }

        if (outputs.newSlot > head) {
            head = outputs.newSlot;
        }

        bytes32 l1StateRoot = outputs.executionStateRoot;
        emit LightClientUpdated(outputs.newSlot, l1StateRoot);

        // 2. MPT prove L1 StateBridge's keccak chain head against the verified L1 state root
        chainHead = ProofsLib.proveStorageSlot(ANCHOR_BRIDGE, _HASH_CHAIN_SLOT, accountProof, storageProof, l1StateRoot);
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

    /// @notice Sets a sync committee Poseidon root for a specific period.
    /// @dev Used for bootstrapping or correcting sync committee state.
    function setSyncCommitteePoseidon(uint256 period, bytes32 poseidon) external virtual onlyOwner {
        syncCommitteePoseidons[period] = poseidon;
        emit SyncCommitteeRotated(period, poseidon);
    }
}
