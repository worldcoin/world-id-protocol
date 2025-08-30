// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {AbstractSignerPubkeyRegistry} from "./AbstractSignerPubkeyRegistry.sol";

contract CredentialIssuerRegistry is AbstractSignerPubkeyRegistry {
    string public constant EIP712_NAME = "CredentialIssuerRegistry";
    string public constant EIP712_VERSION = "1.0";

    string public constant REMOVE_ISSUER_TYPEDEF = "RemoveIssuer(uint256 issuerId,uint256 nonce)";
    string public constant UPDATE_PUBKEY_TYPEDEF =
        "UpdateIssuerPubkey(uint256 issuerId, bytes32 newPubkey, bytes32 oldPubkey, uint256 nonce)";
    string public constant UPDATE_SIGNER_TYPEDEF =
        "UpdateIssuerSigner(uint256 issuerId, address newSigner, uint256 nonce)";

    bytes32 public constant REMOVE_ISSUER_TYPEHASH = keccak256(abi.encodePacked(REMOVE_ISSUER_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));

    event IssuerRegistered(uint256 indexed issuerId, bytes32 pubkey, address signer);
    event IssuerRemoved(uint256 indexed issuerId, bytes32 pubkey, address signer);
    event IssuerPubkeyUpdated(uint256 indexed issuerId, bytes32 oldPubkey, bytes32 newPubkey, address signer);
    event IssuerSignerUpdated(uint256 indexed issuerId, address oldSigner, address newSigner);

    constructor() AbstractSignerPubkeyRegistry(EIP712_NAME, EIP712_VERSION) {}

    function issuerIdToPubkey(uint256 issuerId) public view returns (bytes32) {
        return _idToPubkey[issuerId];
    }

    function addressToIssuerId(address signer) public view returns (uint256) {
        return _addressToId[signer];
    }

    function nextIssuerId() public view returns (uint256) {
        return _nextId;
    }

    function _typehashRemove() internal pure override returns (bytes32) {
        return REMOVE_ISSUER_TYPEHASH;
    }

    function _typehashUpdatePubkey() internal pure override returns (bytes32) {
        return UPDATE_PUBKEY_TYPEHASH;
    }

    function _typehashUpdateSigner() internal pure override returns (bytes32) {
        return UPDATE_SIGNER_TYPEHASH;
    }

    function _emitRegistered(uint256 id, bytes32 pubkey, address signer) internal override {
        emit IssuerRegistered(id, pubkey, signer);
    }

    function _emitRemoved(uint256 id, bytes32 pubkey, address signer) internal override {
        emit IssuerRemoved(id, pubkey, signer);
    }

    function _emitPubkeyUpdated(uint256 id, bytes32 oldPubkey, bytes32 newPubkey, address signer) internal override {
        emit IssuerPubkeyUpdated(id, oldPubkey, newPubkey, signer);
    }

    function _emitSignerUpdated(uint256 id, address oldSigner, address newSigner) internal override {
        emit IssuerSignerUpdated(id, oldSigner, newSigner);
    }
}
