// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ProofsLib} from "./lib/ProofsLib.sol";

/// @dev Thrown when the recovered signer doesn't match the authorized sequencer.
error InvalidSequencerSignature();

/// @dev Thrown when the SSZ payload is too short to contain a state root.
error PayloadTooShort();

/// @dev Thrown when a zero address is provided where one is not allowed.
error ZeroAddress();

/// @notice Emitted when state is successfully relayed from the sequencer.
event StateRelayed(bytes32 indexed payloadHash, bytes32 indexed provenChainHead);

/// @notice Emitted when the sequencer address is updated.
event SequencerUpdated(address indexed oldSequencer, address indexed newSequencer);

/// @dev Minimal interface for the gateway commit path on BridgedWorldID.
interface IBridgedWorldID {
    function commitFromGateway(bytes32 provenChainHead, bytes calldata commitPayload) external;
}

/// @title WorldIDGateway
/// @author World Contributors
/// @notice Gateway that enables the World Chain sequencer to relay state
///   directly to destination chains, bypassing L1 entirely.
///
///   Uses the native OP Stack P2P block signing scheme — the same signature the sequencer
///   already produces for every block. The sequencer's signature attests to the validity
///   of the block's state root.
///
/// @dev Signing scheme (from op-service/signer/blockpayload_args.go):
///   ```
///   payloadHash  = keccak256(sszPayload)
///   signingHash  = keccak256(domain[32] || chainId[32] || payloadHash[32])
///   signature    = secp256k1_sign(signingHash, sequencerKey)
///   ```
///   Where `domain = bytes32(0)` (SigningDomainBlocksV1) and `chainId` is the WC chain ID.
///
/// @dev SSZ layout of ExecutionPayloadEnvelope (from op-service/eth/ssz.go):
///   ```
///   [0:32]   ParentBeaconBlockRoot
///   [32:64]  ParentHash
///   [64:84]  FeeRecipient
///   [84:116] StateRoot              <-- extracted here
///   ```
///
/// @dev Flow:
///   1. Relayer submits the SSZ-encoded ExecutionPayloadEnvelope + P2P signature.
///   2. Gateway computes payloadHash and verifies the OP Stack P2P signature.
///   3. Gateway extracts stateRoot from SSZ offset 84.
///   4. Gateway proves WorldChainBridge's keccak chain head via MPT against the stateRoot.
///   5. Gateway calls `BridgedWorldID.commitFromGateway()` with the proven chain head + commitments.
///   6. BridgedWorldID verifies chain integrity and applies the commitments.
contract WorldIDGateway is Ownable {
    ////////////////////////////////////////////////////////////
    //                       CONSTANTS                        //
    ////////////////////////////////////////////////////////////

    /// @dev OP Stack V1 signing domain — 32 zero bytes.
    ///   See: op-service/signer/block_auth.go `SigningDomainBlocksV1`
    bytes32 public constant SIGNING_DOMAIN = bytes32(0);

    /// @dev Byte offset of StateRoot within SSZ-encoded ExecutionPayloadEnvelope.
    ///   Layout: ParentBeaconBlockRoot(32) + ParentHash(32) + FeeRecipient(20) = 84
    uint256 internal constant STATE_ROOT_SSZ_OFFSET = 84;

    /// @dev Minimum SSZ payload length to contain the state root (84 + 32 = 116).
    uint256 internal constant MIN_SSZ_LENGTH = 116;

    /// @dev Storage slot for WorldChainBridge's keccak chain head (ERC-7201 base slot).
    ///   keccak256(abi.encode(uint256(keccak256("worldid.storage.WorldIDStateBridge")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant WC_CHAIN_HEAD_SLOT = 0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00;

    ////////////////////////////////////////////////////////////
    //                       IMMUTABLES                       //
    ////////////////////////////////////////////////////////////

    /// @notice The BridgedWorldID contract on this destination chain.
    address public immutable BRIDGE;

    /// @notice The WorldChainBridge address on World Chain (MPT proof target).
    address public immutable WC_BRIDGE;

    /// @notice The World Chain chain ID, used in the OP Stack signing hash.
    uint256 public immutable WC_CHAIN_ID;

    ////////////////////////////////////////////////////////////
    //                         STATE                          //
    ////////////////////////////////////////////////////////////

    /// @notice The authorized sequencer signing key (unsafeBlockSigner from SystemConfig).
    address public sequencer;

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    /// @param owner_ The owner who can rotate the sequencer key.
    /// @param sequencer_ The sequencer P2P signing address (unsafeBlockSigner).
    /// @param bridge_ The BridgedWorldID contract on this chain.
    /// @param wcBridge_ The WorldChainBridge address on World Chain.
    /// @param wcChainId_ The World Chain chain ID (e.g. 480).
    constructor(address owner_, address sequencer_, address bridge_, address wcBridge_, uint256 wcChainId_)
        Ownable(owner_)
    {
        if (sequencer_ == address(0)) revert ZeroAddress();
        if (bridge_ == address(0)) revert ZeroAddress();
        if (wcBridge_ == address(0)) revert ZeroAddress();

        sequencer = sequencer_;
        BRIDGE = bridge_;
        WC_BRIDGE = wcBridge_;
        WC_CHAIN_ID = wcChainId_;
    }

    ////////////////////////////////////////////////////////////
    //                         RELAY                          //
    ////////////////////////////////////////////////////////////

    /// @notice Relays World Chain state to the destination bridge.
    /// @dev Permissionless — anyone with a valid sequencer-signed payload + MPT proof can submit.
    /// @param sszPayload The SSZ-encoded ExecutionPayloadEnvelope from the WC sequencer.
    /// @param signature The sequencer's 65-byte P2P signature (r[32] || s[32] || v[1], v=0|1).
    /// @param accountProof MPT account proof for WorldChainBridge on World Chain.
    /// @param storageProof MPT storage proof for slot 0 (keccak chain head) of WorldChainBridge.
    /// @param commitPayload ABI-encoded `ProofsLib.Commitment[]` to apply on the destination bridge.
    function relay(
        bytes calldata sszPayload,
        bytes calldata signature,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof,
        bytes calldata commitPayload
    ) external virtual {
        // 1. Verify the OP Stack P2P signature over the SSZ payload
        bytes32 payloadHash = keccak256(sszPayload);
        _verifySequencerSignature(payloadHash, WC_CHAIN_ID, signature, sequencer);

        // 2. Extract WC state root from SSZ at fixed offset
        if (sszPayload.length < MIN_SSZ_LENGTH) revert PayloadTooShort();
        bytes32 stateRoot;
        assembly {
            stateRoot := calldataload(add(sszPayload.offset, STATE_ROOT_SSZ_OFFSET))
        }

        // 3. MPT proof: read WorldChainBridge's keccak chain head from ERC-7201 slot
        bytes32 storageRoot = ProofsLib.verifyAccountAndGetStorageRoot(WC_BRIDGE, accountProof, stateRoot);
        bytes32 provenChainHead = bytes32(ProofsLib.storageFromProof(storageProof, storageRoot, WC_CHAIN_HEAD_SLOT));

        // 4. Deliver to BridgedWorldID — it verifies chain integrity and applies
        IBridgedWorldID(BRIDGE).commitFromGateway(provenChainHead, commitPayload);

        emit StateRelayed(payloadHash, provenChainHead);
    }

    ////////////////////////////////////////////////////////////
    //                 SIGNATURE VERIFICATION                 //
    ////////////////////////////////////////////////////////////

    /// @dev Verifies the OP Stack P2P block signature.
    ///   signingHash = keccak256(SIGNING_DOMAIN || uint256(chainId) || payloadHash)
    ///   See: op-service/signer/blockpayload_args.go `ToSigningHash()`
    function _verifySequencerSignature(
        bytes32 payloadHash,
        uint256 chainId,
        bytes calldata signature,
        address sequencer_
    ) internal virtual {
        bytes32 signingHash = keccak256(abi.encodePacked(SIGNING_DOMAIN, chainId, payloadHash));
        address signer = ECDSA.recover(signingHash, signature);
        if (signer != sequencer_) revert InvalidSequencerSignature();
    }

    ////////////////////////////////////////////////////////////
    //                    ADMIN FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice Rotates the authorized sequencer signing key.
    function setSequencer(address newSequencer) external virtual onlyOwner {
        if (newSequencer == address(0)) revert ZeroAddress();
        address old = sequencer;
        sequencer = newSequencer;
        emit SequencerUpdated(old, newSequencer);
    }
}
