// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {AbstractSignerPubkeyRegistry} from "./AbstractSignerPubkeyRegistry.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title CredentialSchemaIssuerRegistry
 * @author world
 * @notice A registry of schema+issuer for credentials. Each pair has an ID which is included in each issued Credential as issuerSchemaId.
 */
contract CredentialSchemaIssuerRegistry is AbstractSignerPubkeyRegistry {
    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // Stores the schema URI that contains the schema definition for each issuerSchemaId.
    mapping(uint64 => string) public idToSchemaUri;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "CredentialSchemaIssuerRegistry";
    string public constant EIP712_VERSION = "1.0";

    string public constant REMOVE_ISSUER_SCHEMA_TYPEDEF = "RemoveIssuerSchema(uint64 issuerSchemaId,uint256 nonce)";
    string public constant UPDATE_PUBKEY_TYPEDEF =
        "UpdateIssuerSchemaPubkey(uint64 issuerSchemaId,Pubkey newPubkey,Pubkey oldPubkey,uint256 nonce)";
    string public constant UPDATE_SIGNER_TYPEDEF =
        "UpdateIssuerSchemaSigner(uint64 issuerSchemaId,address newSigner,uint256 nonce)";
    string public constant UPDATE_ISSUER_SCHEMA_URI_TYPEDEF =
        "UpdateIssuerSchemaUri(uint64 issuerSchemaId,string schemaUri)";

    bytes32 public constant REMOVE_ISSUER_SCHEMA_TYPEHASH = keccak256(abi.encodePacked(REMOVE_ISSUER_SCHEMA_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));
    bytes32 public constant UPDATE_ISSUER_SCHEMA_URI_TYPEHASH =
        keccak256(abi.encodePacked(UPDATE_ISSUER_SCHEMA_URI_TYPEDEF));

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event IssuerSchemaRegistered(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaRemoved(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaPubkeyUpdated(uint64 indexed issuerSchemaId, Pubkey oldPubkey, Pubkey newPubkey, address signer);
    event IssuerSchemaSignerUpdated(uint64 indexed issuerSchemaId, address oldSigner, address newSigner);
    event IssuerSchemaUpdated(uint64 indexed issuerSchemaId, string oldSchemaUri, string newSchemaUri);

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    constructor() AbstractSignerPubkeyRegistry(EIP712_NAME, EIP712_VERSION) {}

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    function issuerSchemaIdToPubkey(uint64 issuerSchemaId) public view returns (Pubkey memory) {
        return _idToPubkey[issuerSchemaId];
    }

    function addressToIssuerSchemaId(address signer) public view returns (uint64) {
        return uint64(_addressToId[signer]);
    }

    function nextIssuerSchemaId() public view returns (uint64) {
        return _nextId;
    }

    function _typehashRemove() internal pure override returns (bytes32) {
        return REMOVE_ISSUER_SCHEMA_TYPEHASH;
    }

    function _typehashUpdatePubkey() internal pure override returns (bytes32) {
        return UPDATE_PUBKEY_TYPEHASH;
    }

    function _typehashUpdateSigner() internal pure override returns (bytes32) {
        return UPDATE_SIGNER_TYPEHASH;
    }

    function _emitRegistered(uint64 id, Pubkey memory pubkey, address signer) internal override {
        emit IssuerSchemaRegistered(id, pubkey, signer);
    }

    function _emitRemoved(uint64 id, Pubkey memory pubkey, address signer) internal override {
        emit IssuerSchemaRemoved(id, pubkey, signer);
    }

    function _emitPubkeyUpdated(uint64 id, Pubkey memory oldPubkey, Pubkey memory newPubkey, address signer)
        internal
        override
    {
        emit IssuerSchemaPubkeyUpdated(id, oldPubkey, newPubkey, signer);
    }

    function _emitSignerUpdated(uint64 id, address oldSigner, address newSigner) internal override {
        emit IssuerSchemaSignerUpdated(id, oldSigner, newSigner);
    }

    /**
     * @dev Returns the schema URI for a specific issuerSchemaId.
     * @param issuerSchemaId The issuer+schema ID.
     * @return The schema URI for the issuerSchemaId.
     */
    function getIssuerSchemaUri(uint64 issuerSchemaId) public view returns (string memory) {
        return idToSchemaUri[issuerSchemaId];
    }

    /**
     * @dev Updates the schema URI for a specific issuer schema ID.
     * @param issuerSchemaId The issuer-schema ID whose schema URI will be updated.
     * @param schemaUri The new schema URI to set.
     * @param signature The signature of the issuer authorizing the update.
     */
    function updateIssuerSchemaUri(uint64 issuerSchemaId, string memory schemaUri, bytes calldata signature) public {
        require(issuerSchemaId != 0, "Schema ID not registered");
        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(UPDATE_ISSUER_SCHEMA_URI_TYPEHASH, issuerSchemaId, schemaUri)));
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == issuerSchemaId, "Registry: invalid signature");

        string memory oldSchemaUri = idToSchemaUri[issuerSchemaId];
        idToSchemaUri[issuerSchemaId] = schemaUri;

        emit IssuerSchemaUpdated(issuerSchemaId, oldSchemaUri, schemaUri);
    }
}
