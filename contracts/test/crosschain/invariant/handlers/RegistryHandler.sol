// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MockRegistry, MockIssuerRegistry, MockOprfRegistry} from "../../helpers/Mocks.sol";

/// @title RegistryHandler
/// @notice Invariant-test handler that drives fuzz-randomized registry mutations.
///   Foundry's invariant runner calls exposed functions with random inputs.
contract RegistryHandler {
    MockRegistry public registry;
    MockIssuerRegistry public issuerRegistry;
    MockOprfRegistry public oprfRegistry;

    /// @dev Ghost state tracking which issuer IDs have been registered.
    uint64[] internal _issuerIds;
    mapping(uint64 => bool) internal _issuerRegistered;

    /// @dev Ghost state tracking which OPRF key IDs have been registered.
    uint160[] internal _oprfIds;
    mapping(uint160 => bool) internal _oprfRegistered;

    /// @dev Total number of registry mutations performed by this handler.
    uint256 public totalMutations;

    uint64 constant MAX_ISSUER_ID = 10;
    uint160 constant MAX_OPRF_ID = 10;

    constructor(MockRegistry registry_, MockIssuerRegistry issuerRegistry_, MockOprfRegistry oprfRegistry_) {
        registry = registry_;
        issuerRegistry = issuerRegistry_;
        oprfRegistry = oprfRegistry_;

        // The setUp seeds issuer ID 1 and OPRF ID 1 into the mock registries,
        // so we track them as already registered in ghost state.
        _issuerIds.push(1);
        _issuerRegistered[1] = true;
        _oprfIds.push(1);
        _oprfRegistered[1] = true;
    }

    // ─── Fuzz targets ────────────────────────────────────────────────────────

    /// @notice Mutate the World ID Merkle root to a random non-zero value.
    function updateRoot(uint256 newRoot) external {
        newRoot = _clamp(newRoot, 1, type(uint128).max);
        registry.setLatestRoot(newRoot);
        totalMutations++;
    }

    /// @notice Register (or overwrite) an issuer pubkey with bounded ID and coordinates.
    function registerIssuer(uint64 id, uint256 x, uint256 y) external {
        id = uint64(_clamp(uint256(id), 1, MAX_ISSUER_ID));
        x = _clamp(x, 1, type(uint128).max);
        y = _clamp(y, 1, type(uint128).max);
        issuerRegistry.setPubkey(id, x, y);
        if (!_issuerRegistered[id]) {
            _issuerIds.push(id);
            _issuerRegistered[id] = true;
        }
        totalMutations++;
    }

    /// @notice Update an existing issuer's pubkey. Picks from registered IDs using `seed`.
    function updateIssuer(uint256 seed, uint256 x, uint256 y) external {
        if (_issuerIds.length == 0) return;
        uint64 id = _issuerIds[seed % _issuerIds.length];
        x = _clamp(x, 1, type(uint128).max);
        y = _clamp(y, 1, type(uint128).max);
        issuerRegistry.setPubkey(id, x, y);
        totalMutations++;
    }

    /// @notice Register (or overwrite) an OPRF key with bounded ID and coordinates.
    function registerOprfKey(uint160 id, uint256 x, uint256 y) external {
        id = uint160(_clamp(uint256(id), 1, MAX_OPRF_ID));
        x = _clamp(x, 1, type(uint128).max);
        y = _clamp(y, 1, type(uint128).max);
        oprfRegistry.setKey(id, x, y);
        if (!_oprfRegistered[id]) {
            _oprfIds.push(id);
            _oprfRegistered[id] = true;
        }
        totalMutations++;
    }

    // ─── Ghost state accessors ───────────────────────────────────────────────

    function getRegisteredIssuerIds() external view returns (uint64[] memory) {
        return _issuerIds;
    }

    function getRegisteredOprfIds() external view returns (uint160[] memory) {
        return _oprfIds;
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    /// @dev Clamps `x` into [min, max] without importing StdUtils.
    function _clamp(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        return min + (x % (max - min + 1));
    }
}
