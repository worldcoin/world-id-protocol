// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Lib} from "@world-id-bridge/lib/Lib.sol";
import {WorldIDGateway} from "@world-id-bridge/lib/Gateway.sol";
import "@world-id-bridge/Error.sol";

/// @title PermissionedGatewayAdapter
/// @author World Contributors
/// @notice Simple owner-attested verification adapter. Only the adapter's owner can relay state.
contract PermissionedGatewayAdapter is WorldIDGateway, Ownable {
    using Lib for *;

    /// @inheritdoc WorldIDGateway
    bytes4 public constant override ATTRIBUTE = bytes4(keccak256("chainHead(bytes32)"));

    /// @param owner_ The owner who can relay state.
    /// @param bridge_ The `StateBridge` contract on this chain.
    /// @param anchorSource_ The bridge contract on the Source Chain.
    /// @param wcChainId_ The World Chain chain ID (e.g. 480).
    constructor(address owner_, address bridge_, address anchorSource_, uint256 wcChainId_)
        WorldIDGateway(bridge_, anchorSource_, wcChainId_)
        Ownable(owner_)
    {}

    /// @dev Verifies the caller is the owner and extracts the chain head from attributes.
    ///   Expects a single attribute: `chainHead(bytes32)`.
    function _verifyAndExtract(bytes calldata, bytes memory proofData)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        _checkOwner();

        (chainHead) = abi.decode(proofData, (bytes32));
    }
}
