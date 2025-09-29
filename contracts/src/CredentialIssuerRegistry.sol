// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {AbstractSignerPubkeyRegistry} from "./AbstractSignerPubkeyRegistry.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract CredentialIssuerRegistry is AbstractSignerPubkeyRegistry {
    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    mapping(uint256 => uint256) public issuerSchemaIdToIssuerId;
    mapping(uint256 => string) public issuerSchemaIdToSchemaUri;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "CredentialIssuerRegistry";
    string public constant EIP712_VERSION = "1.0";

    string public constant REMOVE_ISSUER_TYPEDEF = "RemoveIssuer(uint256 issuerId,uint256 nonce)";
    string public constant UPDATE_PUBKEY_TYPEDEF =
        "UpdateIssuerPubkey(uint256 issuerId,Pubkey newPubkey,Pubkey oldPubkey,uint256 nonce)";
    string public constant UPDATE_SIGNER_TYPEDEF =
        "UpdateIssuerSigner(uint256 issuerId,address newSigner,uint256 nonce)";
    string public constant REGISTER_ISSUER_SCHEMA_ID_TYPEDEF =
        "RegisterIssuerSchemaId(uint256 issuerId,uint256 schemaId,string schemaUri)";
    string public constant UPDATE_ISSUER_SCHEMA_URI_TYPEDEF =
        "UpdateIssuerSchemaUri(uint256 issuerSchemaId,string schemaUri)";

    bytes32 public constant REMOVE_ISSUER_TYPEHASH = keccak256(abi.encodePacked(REMOVE_ISSUER_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));
    bytes32 public constant REGISTER_ISSUER_SCHEMA_ID_TYPEHASH =
        keccak256(abi.encodePacked(REGISTER_ISSUER_SCHEMA_ID_TYPEDEF));
    bytes32 public constant UPDATE_ISSUER_SCHEMA_URI_TYPEHASH =
        keccak256(abi.encodePacked(UPDATE_ISSUER_SCHEMA_URI_TYPEDEF));

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event IssuerRegistered(uint256 indexed issuerId, Pubkey pubkey, address signer);
    event IssuerRemoved(uint256 indexed issuerId, Pubkey pubkey, address signer);
    event IssuerPubkeyUpdated(uint256 indexed issuerId, Pubkey oldPubkey, Pubkey newPubkey, address signer);
    event IssuerSignerUpdated(uint256 indexed issuerId, address oldSigner, address newSigner);
    event IssuerSchemaIdRegistered(uint256 indexed issuerSchemaId, uint256 indexed issuerId, string schemaUri);
    event IssuerSchemaUriUpdated(uint256 indexed issuerSchemaId, string schemaUri);

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    constructor() AbstractSignerPubkeyRegistry(EIP712_NAME, EIP712_VERSION) {}

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    function issuerIdToPubkey(uint256 issuerId) public view returns (Pubkey memory) {
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

    function _emitRegistered(uint256 id, Pubkey memory pubkey, address signer) internal override {
        emit IssuerRegistered(id, pubkey, signer);
    }

    function _emitRemoved(uint256 id, Pubkey memory pubkey, address signer) internal override {
        emit IssuerRemoved(id, pubkey, signer);
    }

    function _emitPubkeyUpdated(uint256 id, Pubkey memory oldPubkey, Pubkey memory newPubkey, address signer)
        internal
        override
    {
        emit IssuerPubkeyUpdated(id, oldPubkey, newPubkey, signer);
    }

    function _emitSignerUpdated(uint256 id, address oldSigner, address newSigner) internal override {
        emit IssuerSignerUpdated(id, oldSigner, newSigner);
    }

    /**
     * @dev Registers an issuerSchemaID.
     * @param issuerSchemaId The issuer-schema ID. Unique identifier per-issuer, per-schema.
     * @param id The issuer ID.
     * @param schemaUri The schema URI. Generally a globally defined schema URI.
     * @param signature The signature of the issuer.
     */
    function registerIssuerSchemaId(
        uint256 issuerSchemaId,
        uint256 id,
        string memory schemaUri,
        bytes calldata signature
    ) public onlyOwner {
        require(issuerSchemaIdToIssuerId[issuerSchemaId] == 0, "Schema ID already registered");
        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(REGISTER_ISSUER_SCHEMA_ID_TYPEHASH, issuerSchemaId, id, schemaUri)));
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == id, "Registry: invalid signature");

        issuerSchemaIdToIssuerId[issuerSchemaId] = id;
        issuerSchemaIdToSchemaUri[issuerSchemaId] = schemaUri;

        emit IssuerSchemaIdRegistered(issuerSchemaId, id, schemaUri);
    }

    /**
     * @dev Removes an issuer schema ID.
     * @param issuerSchemaId The issuer-schema ID.
     * @param schemaUri The new schema URI.
     * @param signature The signature of the issuer.
     */
    function updateIssuerSchemaUri(uint256 issuerSchemaId, string memory schemaUri, bytes calldata signature) public {
        require(issuerSchemaIdToIssuerId[issuerSchemaId] != 0, "Schema ID not registered");
        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(UPDATE_ISSUER_SCHEMA_URI_TYPEHASH, issuerSchemaId, schemaUri)));
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == issuerSchemaIdToIssuerId[issuerSchemaId], "invalid signature");

        issuerSchemaIdToSchemaUri[issuerSchemaId] = schemaUri;

        emit IssuerSchemaUriUpdated(issuerSchemaId, schemaUri);
    }
}
