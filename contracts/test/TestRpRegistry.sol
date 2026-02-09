// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {RpRegistry} from "../src/RpRegistry.sol";
import {IRpRegistry} from "../src/interfaces/IRpRegistry.sol";

contract TestRpRegistry is RpRegistry {
    function updateRpUnchecked(
        uint64 rpId,
        uint160 oprfKeyId,
        address manager,
        address signer,
        bool toggleActive,
        string calldata unverifiedWellKnownDomain
    ) public {
        if (oprfKeyId != 0) {
            _relyingParties[rpId].oprfKeyId = oprfKeyId;
        }

        if (manager != address(0)) {
            _relyingParties[rpId].manager = manager;
        }

        if (signer != address(0)) {
            _relyingParties[rpId].signer = signer;
        }

        if (keccak256(bytes(unverifiedWellKnownDomain)) != NO_UPDATE_HASH) {
            _relyingParties[rpId].unverifiedWellKnownDomain = unverifiedWellKnownDomain;
        }

        if (toggleActive) {
            _relyingParties[rpId].active = !_relyingParties[rpId].active;
        }

        emit IRpRegistry.RpUpdated(
            rpId,
            _relyingParties[rpId].oprfKeyId,
            _relyingParties[rpId].active,
            _relyingParties[rpId].manager,
            _relyingParties[rpId].signer,
            _relyingParties[rpId].unverifiedWellKnownDomain
        );
    }
}
