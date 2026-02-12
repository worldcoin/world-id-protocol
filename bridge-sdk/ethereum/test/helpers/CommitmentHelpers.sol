// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofsLib} from "../../src/lib/ProofsLib.sol";
import {INativeReceiver} from "../../src/core/interfaces/INativeReceiver.sol";

/// @title CommitmentHelpers
/// @notice Shared test helper base providing commitment builders, action selectors,
///   assertion utilities, and common test values. Inherited by both `BridgeAdapterBaseTest`
///   and `WormholeBridgeBaseTest` to eliminate duplication.
abstract contract CommitmentHelpers is Test {
    // ── Action selectors (matching ProofsLib) ──
    bytes4 internal constant UPDATE_ROOT_SEL = bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"));
    bytes4 internal constant SET_ISSUER_SEL = bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"));
    bytes4 internal constant SET_OPRF_SEL = bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"));
    bytes4 internal constant INVALIDATE_SEL = bytes4(keccak256("invalidateProofId(bytes32)"));

    // ── Wire format constants ──
    uint8 internal constant PAYLOAD_VERSION = 0x01;
    uint8 internal constant ACTION_COMMIT_FROM_L1 = 0x01;

    // ── Common test values ──
    uint256 internal constant TEST_ROOT = 0x1234567890ABCDEF;
    uint256 internal constant TEST_TIMESTAMP = 1_700_000_000;
    bytes32 internal constant TEST_PROOF_ID = bytes32(uint256(42));
    bytes32 internal constant TEST_BLOCK_HASH = bytes32(uint256(0xBEEF));
    uint64 internal constant TEST_ISSUER_ID = 0x5a7400653dd6d18a;
    uint160 internal constant TEST_OPRF_ID = uint160(TEST_ISSUER_ID);

    // ── Commitment builders (with explicit blockHash) ──

    /// @dev Builds an updateRoot commitment with the given blockHash.
    function _makeUpdateRootCommitment(uint256 root, uint256 ts, bytes32 proofId, bytes32 blockHash)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return ProofsLib.Commitment({
            blockHash: blockHash, data: abi.encodeWithSelector(UPDATE_ROOT_SEL, root, ts, proofId)
        });
    }

    /// @dev Builds an updateRoot commitment with an auto-derived blockHash.
    function _makeUpdateRootCommitment(uint256 root, uint256 ts, bytes32 proofId)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return _makeUpdateRootCommitment(root, ts, proofId, keccak256(abi.encode(root)));
    }

    /// @dev Builds a setIssuerPubkey commitment with the given blockHash.
    function _makeSetIssuerCommitment(uint64 schemaId, uint256 x, uint256 y, bytes32 proofId, bytes32 blockHash)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return ProofsLib.Commitment({
            blockHash: blockHash, data: abi.encodeWithSelector(SET_ISSUER_SEL, schemaId, x, y, proofId)
        });
    }

    /// @dev Builds a setIssuerPubkey commitment with an auto-derived blockHash.
    function _makeSetIssuerCommitment(uint64 schemaId, uint256 x, uint256 y, bytes32 proofId)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return _makeSetIssuerCommitment(schemaId, x, y, proofId, keccak256(abi.encode(schemaId)));
    }

    /// @dev Builds a setOprfKey commitment with the given blockHash.
    function _makeSetOprfCommitment(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId, bytes32 blockHash)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return ProofsLib.Commitment({
            blockHash: blockHash, data: abi.encodeWithSelector(SET_OPRF_SEL, oprfKeyId, x, y, proofId)
        });
    }

    /// @dev Builds a setOprfKey commitment with an auto-derived blockHash.
    function _makeSetOprfCommitment(uint160 oprfKeyId, uint256 x, uint256 y, bytes32 proofId)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return _makeSetOprfCommitment(oprfKeyId, x, y, proofId, keccak256(abi.encode(oprfKeyId)));
    }

    /// @dev Builds an invalidateProofId commitment with the given blockHash.
    function _makeInvalidateCommitment(bytes32 proofId, bytes32 blockHash)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return ProofsLib.Commitment({blockHash: blockHash, data: abi.encodeWithSelector(INVALIDATE_SEL, proofId)});
    }

    /// @dev Builds an invalidateProofId commitment with an auto-derived blockHash.
    function _makeInvalidateCommitment(bytes32 proofId) internal pure returns (ProofsLib.Commitment memory) {
        return _makeInvalidateCommitment(proofId, keccak256(abi.encode(proofId)));
    }

    /// @dev Builds a raw commitment with arbitrary data.
    function _makeRawCommitment(bytes32 blockHash, bytes memory data)
        internal
        pure
        returns (ProofsLib.Commitment memory)
    {
        return ProofsLib.Commitment({blockHash: blockHash, data: data});
    }

    // ── Encoding helpers ──

    /// @dev Builds the standard `commitFromL1` ABI calldata that L1Relay.dispatch() produces.
    function _encodeCommitFromL1(ProofsLib.Commitment[] memory commits) internal pure returns (bytes memory) {
        return abi.encodeCall(INativeReceiver.commitFromL1, (commits));
    }

    // ── Assertion helpers ──

    /// @dev Asserts two commitments are equal (blockHash + data).
    function _assertCommitmentsEqual(ProofsLib.Commitment memory a, ProofsLib.Commitment memory b) internal pure {
        assertEq(a.blockHash, b.blockHash, "blockHash mismatch");
        assertEq(a.data, b.data, "data mismatch");
    }

    // ── Chain hash helpers ──

    /// @dev Computes keccak chain head from initial head + single commitment.
    function _chainHash(bytes32 head, ProofsLib.Commitment memory c) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(head, c.blockHash, c.data));
    }
}
