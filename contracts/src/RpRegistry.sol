// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {AbstractSignerPubkeyRegistry} from "./AbstractSignerPubkeyRegistry.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract RpRegistry is AbstractSignerPubkeyRegistry {
    mapping(uint256 => uint256) public actionValidity;
    mapping(uint256 => uint256) public nextActionId;

    // Keep constants and events for ABI stability and off-chain use
    string public constant EIP712_NAME = "RpRegistry";
    string public constant EIP712_VERSION = "1.0";

    string public constant REMOVE_RP_TYPEDEF = "RemoveRp(uint256 rpId,uint256 nonce)";
    string public constant UPDATE_PUBKEY_TYPEDEF =
        "UpdatePubkey(uint256 rpId, bytes32 newPubkey, bytes32 oldPubkey, uint256 nonce)";
    string public constant UPDATE_SIGNER_TYPEDEF = "UpdateSigner(uint256 rpId, address newSigner, uint256 nonce)";
    string public constant REGISTER_ACTION_TYPEDEF =
        "RegisterAction(uint256 rpId, uint256 validityDuration, uint256 nonce)";

    bytes32 public constant REMOVE_RP_TYPEHASH = keccak256(abi.encodePacked(REMOVE_RP_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));
    bytes32 public constant REGISTER_ACTION_TYPEHASH = keccak256(abi.encodePacked(REGISTER_ACTION_TYPEDEF));

    event RpRegistered(uint256 indexed rpId, bytes32 pubkey, address signer);
    event RpRemoved(uint256 indexed rpId, bytes32 pubkey, address signer);
    event PubkeyUpdated(uint256 indexed rpId, bytes32 oldPubkey, bytes32 newPubkey, address signer);
    event SignerUpdated(uint256 indexed rpId, address oldSigner, address newSigner);
    event ActionRegistered(uint256 indexed rpId, uint256 actionId, uint256 validityDuration);

    constructor() AbstractSignerPubkeyRegistry(EIP712_NAME, EIP712_VERSION) {}

    /**
     * @dev Registers an action for an RP.
     * @param rpId The ID of the RP.
     * @param validityDuration The validity duration of the action.
     * @param signature The signature of the action.
     */
    function registerAction(uint256 rpId, uint256 validityDuration, bytes calldata signature) public onlyOwner {
        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(REGISTER_ACTION_TYPEHASH, rpId, validityDuration, _nonces[rpId])));
        address signer = ECDSA.recover(hash, signature);
        require(signer != address(0), "Invalid signature");
        require(_addressToId[signer] == rpId, "Signer not registered for this RP");
        uint256 actionIdPacked = rpId << 128 | nextActionId[rpId];
        require(actionValidity[actionIdPacked] == 0, "Action already registered");
        actionValidity[actionIdPacked] = block.timestamp + validityDuration;
        emit ActionRegistered(rpId, nextActionId[rpId], validityDuration);
        nextActionId[rpId]++;
        _nonces[rpId]++;
    }

    /**
     * @dev Checks if an action is valid.
     * @param rpId The ID of the RP.
     * @param actionId The ID of the action.
     * @return True if the action is valid, false otherwise.
     */
    function isActionValid(uint256 rpId, uint256 actionId) public view returns (bool) {
        uint256 actionIdPacked = rpId << 128 | actionId;
        return actionValidity[actionIdPacked] > block.timestamp;
    }

    function rpIdToPubkey(uint256 rpId) public view returns (bytes32) {
        return _idToPubkey[rpId];
    }

    function addressToRpId(address signer) public view returns (uint256) {
        return _addressToId[signer];
    }

    function nextRpId() public view returns (uint256) {
        return _nextId;
    }

    function _typehashRemove() internal pure override returns (bytes32) {
        return REMOVE_RP_TYPEHASH;
    }

    function _typehashUpdatePubkey() internal pure override returns (bytes32) {
        return UPDATE_PUBKEY_TYPEHASH;
    }

    function _typehashUpdateSigner() internal pure override returns (bytes32) {
        return UPDATE_SIGNER_TYPEHASH;
    }

    function _emitRegistered(uint256 id, bytes32 pubkey, address signer) internal override {
        emit RpRegistered(id, pubkey, signer);
    }

    function _emitRemoved(uint256 id, bytes32 pubkey, address signer) internal override {
        emit RpRemoved(id, pubkey, signer);
    }

    function _emitPubkeyUpdated(uint256 id, bytes32 oldPubkey, bytes32 newPubkey, address signer) internal override {
        emit PubkeyUpdated(id, oldPubkey, newPubkey, signer);
    }

    function _emitSignerUpdated(uint256 id, address oldSigner, address newSigner) internal override {
        emit SignerUpdated(id, oldSigner, newSigner);
    }
}
