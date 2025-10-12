// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title CredentialSchemaIssuerRegistry
 * @author world
 * @notice A registry of schema+issuer for credentials. Each pair has an ID which is included in each issued Credential as issuerSchemaId.
 */
contract CredentialSchemaIssuerRegistry is EIP712, Ownable {
    ////////////////////////////////////////////////////////////
    //                         Types                          //
    ////////////////////////////////////////////////////////////

    struct Pubkey {
        uint256 x;
        uint256 y;
    }

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    mapping(uint256 => Pubkey) private _idToPubkey;
    mapping(address => uint256) private _addressToId;
    uint256 private _nextId = 1;
    mapping(uint256 => uint256) private _nonces;

    // Stores the schema URI that contains the schema definition for each issuerSchemaId.
    mapping(uint256 => string) public idToSchemaUri;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "CredentialSchemaIssuerRegistry";
    string public constant EIP712_VERSION = "1.0";

    string public constant REMOVE_ISSUER_SCHEMA_TYPEDEF = "RemoveIssuerSchema(uint256 issuerSchemaId,uint256 nonce)";
    string public constant UPDATE_PUBKEY_TYPEDEF =
        "UpdateIssuerSchemaPubkey(uint256 issuerSchemaId,Pubkey newPubkey,Pubkey oldPubkey,uint256 nonce)";
    string public constant UPDATE_SIGNER_TYPEDEF =
        "UpdateIssuerSchemaSigner(uint256 issuerSchemaId,address newSigner,uint256 nonce)";
    string public constant UPDATE_ISSUER_SCHEMA_URI_TYPEDEF =
        "UpdateIssuerSchemaUri(uint256 issuerSchemaId,string schemaUri)";

    bytes32 public constant REMOVE_ISSUER_SCHEMA_TYPEHASH = keccak256(abi.encodePacked(REMOVE_ISSUER_SCHEMA_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));
    bytes32 public constant UPDATE_ISSUER_SCHEMA_URI_TYPEHASH =
        keccak256(abi.encodePacked(UPDATE_ISSUER_SCHEMA_URI_TYPEDEF));

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event IssuerSchemaRegistered(uint256 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaRemoved(uint256 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaPubkeyUpdated(uint256 indexed issuerSchemaId, Pubkey oldPubkey, Pubkey newPubkey, address signer);
    event IssuerSchemaSignerUpdated(uint256 indexed issuerSchemaId, address oldSigner, address newSigner);
    event IssuerSchemaUpdated(uint256 indexed issuerSchemaId, string oldSchemaUri, string newSchemaUri);

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    constructor() EIP712(EIP712_NAME, EIP712_VERSION) Ownable(msg.sender) {}

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    function register(Pubkey memory pubkey, address signer) public onlyOwner {
        require(pubkey.x != 0 && pubkey.y != 0, "Registry: pubkey cannot be zero");
        require(signer != address(0), "Registry: signer cannot be zero address");
        require(_addressToId[signer] == 0, "Registry: signer already registered");

        uint256 issuerSchemaId = _nextId;
        _idToPubkey[issuerSchemaId] = pubkey;
        _addressToId[signer] = issuerSchemaId;
        emit IssuerSchemaRegistered(issuerSchemaId, pubkey, signer);
        _nextId = issuerSchemaId + 1;
    }

    function remove(uint256 issuerSchemaId, bytes calldata signature) public onlyOwner {
        Pubkey memory pubkey = _idToPubkey[issuerSchemaId];
        require(!_isEmptyPubkey(pubkey), "Registry: id not registered");
        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(REMOVE_ISSUER_SCHEMA_TYPEHASH, issuerSchemaId, _nonces[issuerSchemaId])));
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == issuerSchemaId, "Registry: invalid signature");

        emit IssuerSchemaRemoved(issuerSchemaId, pubkey, signer);

        _nonces[issuerSchemaId]++;
        delete _idToPubkey[issuerSchemaId];
        delete _addressToId[signer];
        delete idToSchemaUri[issuerSchemaId];
    }

    function updatePubkey(uint256 issuerSchemaId, Pubkey memory newPubkey, bytes calldata signature)
        public
        onlyOwner
    {
        Pubkey memory oldPubkey = _idToPubkey[issuerSchemaId];
        require(!_isEmptyPubkey(oldPubkey), "Registry: id not registered");
        require(!_isEmptyPubkey(newPubkey), "Registry: newPubkey cannot be zero");
        bytes32 hash = _hashTypedDataV4(
            keccak256(abi.encode(UPDATE_PUBKEY_TYPEHASH, issuerSchemaId, newPubkey, oldPubkey, _nonces[issuerSchemaId]))
        );
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == issuerSchemaId, "Registry: invalid signature");

        _idToPubkey[issuerSchemaId] = newPubkey;
        emit IssuerSchemaPubkeyUpdated(issuerSchemaId, oldPubkey, newPubkey, signer);

        _nonces[issuerSchemaId]++;
    }

    function updateSigner(uint256 issuerSchemaId, address newSigner, bytes calldata signature) public onlyOwner {
        require(!_isEmptyPubkey(_idToPubkey[issuerSchemaId]), "Registry: id not registered");
        require(newSigner != address(0), "Registry: newSigner cannot be zero address");
        require(_addressToId[newSigner] == 0, "Registry: newSigner already registered");

        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(UPDATE_SIGNER_TYPEHASH, issuerSchemaId, newSigner, _nonces[issuerSchemaId])));
        address oldSigner = ECDSA.recover(hash, signature);
        require(_addressToId[oldSigner] == issuerSchemaId, "Registry: invalid signature");

        _addressToId[newSigner] = issuerSchemaId;
        delete _addressToId[oldSigner];
        emit IssuerSchemaSignerUpdated(issuerSchemaId, oldSigner, newSigner);

        _nonces[issuerSchemaId]++;
    }

    /**
     * @dev Returns the schema URI for a specific issuerSchemaId.
     * @param issuerSchemaId The issuer+schema ID.
     * @return The schema URI for the issuerSchemaId.
     */
    function getIssuerSchemaUri(uint256 issuerSchemaId) public view returns (string memory) {
        return idToSchemaUri[issuerSchemaId];
    }

    /**
     * @dev Updates the schema URI for a specific issuer schema ID.
     * @param issuerSchemaId The issuer-schema ID whose schema URI will be updated.
     * @param schemaUri The new schema URI to set.
     * @param signature The signature of the issuer authorizing the update.
     */
    function updateIssuerSchemaUri(uint256 issuerSchemaId, string memory schemaUri, bytes calldata signature) public {
        require(issuerSchemaId != 0, "Schema ID not registered");
        bytes32 hash =
            _hashTypedDataV4(keccak256(abi.encode(UPDATE_ISSUER_SCHEMA_URI_TYPEHASH, issuerSchemaId, schemaUri)));
        address signer = ECDSA.recover(hash, signature);
        require(_addressToId[signer] == issuerSchemaId, "Registry: invalid signature");

        string memory oldSchemaUri = idToSchemaUri[issuerSchemaId];
        idToSchemaUri[issuerSchemaId] = schemaUri;

        emit IssuerSchemaUpdated(issuerSchemaId, oldSchemaUri, schemaUri);
    }

    function issuerSchemaIdToPubkey(uint256 issuerSchemaId) public view returns (Pubkey memory) {
        return _idToPubkey[issuerSchemaId];
    }

    function addressToIssuerSchemaId(address signer) public view returns (uint256) {
        return _addressToId[signer];
    }

    function nextIssuerSchemaId() public view returns (uint256) {
        return _nextId;
    }

    function nonceOf(uint256 issuerSchemaId) public view returns (uint256) {
        return _nonces[issuerSchemaId];
    }

    function _isEmptyPubkey(Pubkey memory pubkey) internal pure returns (bool) {
        return pubkey.x == 0 && pubkey.y == 0;
    }
}
