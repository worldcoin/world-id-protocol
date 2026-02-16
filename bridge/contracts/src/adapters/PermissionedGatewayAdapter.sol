// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {Lib} from "@lib-core/Lib.sol";
import {WorldIDGateway} from "@lib-core/Gateway.sol";
import "../Error.sol";

/// @title PermissionedGatewayAdapter
/// @author World Contributors
/// @notice Simple owner-attested verification adapter. Only the adapter's owner can relay state.
contract PermissionedGatewayAdapter is WorldIDGateway, Ownable {
    using Lib for *;

    /// @param owner_ The owner who can relay state.
    /// @param bridge_ The `StateBridge` contract on this chain.
    /// @param anchorSource_ The bridge contract on the Source Chain.
    /// @param wcChainId_ The World Chain chain ID (e.g. 480).
    constructor(address owner_, address bridge_, address anchorSource_, uint256 wcChainId_)
        WorldIDGateway(bridge_, anchorSource_, wcChainId_)
        Ownable(owner_)
    {}

    /// @inheritdoc WorldIDGateway
    function supportsAttribute(bytes4 selector) public view virtual override returns (bool) {
        return selector == OWNED_GATEWAY_ATTRIBUTES;
    }

    /// @dev Verifies the caller is the owner and extracts the chain head from attributes.
    ///   Expects a single attribute: `chainHead(bytes32)`.
    function _verifyAndExtract(bytes calldata, bytes[] calldata attributes)
        internal
        virtual
        override
        returns (bytes32 chainHead)
    {
        _checkOwner();

        (bytes4 selector, bytes memory data) = split(attributes[0]);
        if (!supportsAttribute(selector)) {
            revert MissingAttribute(OWNED_GATEWAY_ATTRIBUTES);
        }

        (chainHead) = abi.decode(data, (bytes32));
    }
}
