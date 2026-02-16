// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {Gateway} from "./Gateway.sol";
import {Attributes} from "./Attributes.sol";
import "../Error.sol";

/// @title OwnedGateway
/// @author World Contributors
/// @notice Simple owner-attested ERC-7786 gateway for relaying World ID state to destination chains.
///   The owner (EOA, multisig, or bot) watches `ChainCommitted` events on World Chain and
///   submits the chain head + commitments via `sendMessage`. Trust assumption: the owner is honest.
///
/// @dev This is the simplest possible gateway — no proofs, no signatures beyond the owner's tx.
///   Suitable for day-1 deployment while more sophisticated trust models are built out.
contract OwnedGateway is Gateway, Ownable {
    /// @param owner_ The owner who can relay state.
    /// @param bridge_ The WorldIDBridge contract on this chain.
    /// @param wcSource_ The WorldIDSource address on World Chain.
    /// @param wcChainId_ The World Chain chain ID (e.g. 480).
    constructor(address owner_, address bridge_, address wcSource_, uint256 wcChainId_)
        Gateway(bridge_, wcSource_, wcChainId_)
        Ownable(owner_)
    {}

    /// @inheritdoc Gateway
    function supportsAttribute(bytes4 selector) external view virtual override returns (bool) {
        return selector == Attributes.OWNED_GATEWAY_ATTRIBUTES;
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

        (bytes4 selector, bytes memory data) = Attributes.split(attributes[0]);
        if (selector != Attributes.OWNED_GATEWAY_ATTRIBUTES) {
            revert MissingAttribute(Attributes.OWNED_GATEWAY_ATTRIBUTES);
        }

        (chainHead) = abi.decode(data, (bytes32));
    }
}
