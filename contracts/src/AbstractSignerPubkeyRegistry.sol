// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title AbstractSignerPubkeyRegistry
 * @notice Base contract for registries that map incrementing ids to pubkeys and authorized signers.
 * @dev Children must provide EIP-712 typehashes via `_typehash*` overrides and emit
 *      domain-specific events via the `_emit*` hook functions.
 */
abstract contract AbstractSignerPubkeyRegistry is EIP712, Ownable {
    // Storage
    mapping(uint256 => bytes32) internal _idToPubkey;
    mapping(address => uint256) internal _addressToId;
    uint256 internal _nextId = 1;
    // Per-id EIP-712 nonce to prevent signature replay across updates
    mapping(uint256 => uint256) internal _nonces;

    /**
     * @dev Initializes the EIP-712 domain and sets the deployer as the initial owner.
     * @param eip712Name The EIP-712 domain name.
     * @param eip712Version The EIP-712 domain version.
     */
    constructor(string memory eip712Name, string memory eip712Version)
        EIP712(eip712Name, eip712Version)
        Ownable(msg.sender)
    {}

    /**
     * @dev Returns the EIP-712 typehash for the Remove struct used by `remove`.
     */
    function _typehashRemove() internal pure virtual returns (bytes32);

    /**
     * @dev Returns the EIP-712 typehash for the UpdatePubkey struct used by `updatePubkey`.
     */
    function _typehashUpdatePubkey() internal pure virtual returns (bytes32);

    /**
     * @dev Returns the EIP-712 typehash for the UpdateSigner struct used by `updateSigner`.
     */
    function _typehashUpdateSigner() internal pure virtual returns (bytes32);

    /**
     * @dev Hook for children to emit a domain-specific "registered" event.
     * @param id The newly assigned id.
     * @param pubkey The registered pubkey.
     * @param signer The authorized signer for this id.
     */
    function _emitRegistered(uint256 id, bytes32 pubkey, address signer) internal virtual;

    /**
     * @dev Hook for children to emit a domain-specific "removed" event.
     * @param id The removed id.
     * @param pubkey The pubkey that was associated with the id.
     * @param signer The signer that authorized the removal.
     */
    function _emitRemoved(uint256 id, bytes32 pubkey, address signer) internal virtual;

    /**
     * @dev Hook for children to emit a domain-specific "pubkey updated" event.
     * @param id The id whose pubkey changed.
     * @param oldPubkey The previous pubkey.
     * @param newPubkey The new pubkey.
     * @param signer The signer that authorized the change.
     */
    function _emitPubkeyUpdated(uint256 id, bytes32 oldPubkey, bytes32 newPubkey, address signer) internal virtual;

    /**
     * @dev Hook for children to emit a domain-specific "signer updated" event.
     * @param id The id whose signer changed.
     * @param oldSigner The previous signer.
     * @param newSigner The new signer.
     */
    function _emitSignerUpdated(uint256 id, address oldSigner, address newSigner) internal virtual;

    /**
     * @dev Registers a new id with `pubkey` and `signer`.
     *      Only callable by the contract owner.
     *
     * Reverts if:
     * - `pubkey` is zero.
     * - `signer` is the zero address.
     * - `signer` is already registered.
     *
     * @param pubkey The pubkey to associate with the new id.
     * @param signer The address authorized to sign EIP-712 updates for this id.
     */
    function register(bytes32 pubkey, address signer) public onlyOwner {
        require(pubkey != bytes32(0), "Registry: pubkey cannot be zero");
        require(signer != address(0), "Registry: signer cannot be zero address");
        require(_addressToId[signer] == 0, "Registry: signer already registered");

        uint256 id = _nextId;
        _idToPubkey[id] = pubkey;
        _addressToId[signer] = id;
        _emitRegistered(id, pubkey, signer);
        _nextId = id + 1;
    }

    /**
     * @dev Removes an existing id. Requires a valid EIP-712 signature from the current signer of `id`.
     *      Only callable by the contract owner.
     *
     * Reverts if:
     * - `id` is not registered.
     * - the provided `signature` does not recover to the signer currently bound to `id`.
     *
     * @param id The id to remove.
     * @param signature The EIP-712 signature authorizing the removal.
     */
    function remove(uint256 id, bytes calldata signature) public onlyOwner {
        require(_idToPubkey[id] != bytes32(0), "Registry: id not registered");
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(_typehashRemove(), id, _nonces[id])));
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == id, "Registry: invalid signature");

        bytes32 oldPubkey = _idToPubkey[id];
        _emitRemoved(id, oldPubkey, signer);

        _nonces[id]++;
        delete _idToPubkey[id];
        delete _addressToId[signer];
    }

    /**
     * @dev Updates the pubkey for an existing `id`. Requires a valid EIP-712 signature from the current signer of `id`.
     *      Only callable by the contract owner.
     *
     * Reverts if:
     * - `id` is not registered.
     * - `newPubkey` is zero.
     * - the provided `signature` does not recover to the signer currently bound to `id`.
     *
     * @param id The id to update.
     * @param newPubkey The new pubkey to associate with `id`.
     * @param signature The EIP-712 signature authorizing the pubkey change.
     */
    function updatePubkey(uint256 id, bytes32 newPubkey, bytes calldata signature) public onlyOwner {
        bytes32 oldPubkey = _idToPubkey[id];
        require(oldPubkey != bytes32(0), "Registry: id not registered");
        require(newPubkey != bytes32(0), "Registry: newPubkey cannot be zero");
        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(_typehashUpdatePubkey(), id, newPubkey, oldPubkey, _nonces[id])));
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == id, "Registry: invalid signature");

        _idToPubkey[id] = newPubkey;
        _emitPubkeyUpdated(id, oldPubkey, newPubkey, signer);

        _nonces[id]++;
    }

    /**
     * @dev Updates the signer for an existing `id`. Requires a valid EIP-712 signature from the current signer of `id`.
     *      Only callable by the contract owner.
     *
     * Reverts if:
     * - `id` is not registered.
     * - `newSigner` is the zero address.
     * - `newSigner` is already registered to a different id.
     * - the provided `signature` does not recover to the signer currently bound to `id`.
     *
     * @param id The id whose signer is being updated.
     * @param newSigner The address to set as the new signer for `id`.
     * @param signature The EIP-712 signature authorizing the signer change.
     */
    function updateSigner(uint256 id, address newSigner, bytes calldata signature) public onlyOwner {
        require(_idToPubkey[id] != bytes32(0), "Registry: id not registered");
        require(newSigner != address(0), "Registry: newSigner cannot be zero address");
        require(_addressToId[newSigner] == 0, "Registry: newSigner already registered");

        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(_typehashUpdateSigner(), id, newSigner, _nonces[id])));
        address oldSigner = ECDSA.recover(hash, signature);
        require(_addressToId[oldSigner] == id, "Registry: invalid signature");

        _addressToId[newSigner] = id;
        delete _addressToId[oldSigner];
        _emitSignerUpdated(id, oldSigner, newSigner);

        _nonces[id]++;
    }

    /**
     * @dev Returns the current nonce for the given id.
     */
    function nonceOf(uint256 id) public view returns (uint256) {
        return _nonces[id];
    }

    // (no helper getters; children can access internal storage directly)
}
