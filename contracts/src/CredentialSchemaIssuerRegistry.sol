// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title CredentialSchemaIssuerRegistry
 * @author world
 * @notice A registry of schema+issuer for credentials. Each pair has an ID which is included in each issued Credential as issuerSchemaId.
 */
contract CredentialSchemaIssuerRegistry is
    Initializable,
    EIP712Upgradeable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable
{
    error ImplementationNotInitialized();

    /**
     * @dev Thrown when trying to update the schema URI to the same as the current one.
     */
    error SchemaUriIsTheSameAsCurrentOne();

    /**
     * @dev Thrown when the provided signature is invalid for the operation.
     */
    error InvalidSignature();

    /**
     * @dev Thrown when the provided pubkey is invalid (for example if either coordinate is zero).
     */
    error InvalidPubkey();

    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    function _onlyInitialized() internal view {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
    }

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

    // Stores the on-chain signer address for each issuerSchemaId, i.e. who is authorized to perform updates on the issuerSchemaId.
    mapping(uint256 => address) private _idToAddress;

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
        "UpdateIssuerSchemaPubkey(uint256 issuerSchemaId,Pubkey newPubkey,Pubkey oldPubkey,uint256 nonce)Pubkey(uint256 x,uint256 y)";
    string public constant UPDATE_SIGNER_TYPEDEF =
        "UpdateIssuerSchemaSigner(uint256 issuerSchemaId,address newSigner,uint256 nonce)";
    string public constant UPDATE_ISSUER_SCHEMA_URI_TYPEDEF =
        "UpdateIssuerSchemaUri(uint256 issuerSchemaId,string schemaUri,uint256 nonce)";
    string public constant PUBKEY_TYPEDEF = "Pubkey(uint256 x,uint256 y)";

    bytes32 public constant REMOVE_ISSUER_SCHEMA_TYPEHASH = keccak256(abi.encodePacked(REMOVE_ISSUER_SCHEMA_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));
    bytes32 public constant UPDATE_ISSUER_SCHEMA_URI_TYPEHASH =
        keccak256(abi.encodePacked(UPDATE_ISSUER_SCHEMA_URI_TYPEDEF));
    bytes32 public constant PUBKEY_TYPEHASH = keccak256(abi.encodePacked(PUBKEY_TYPEDEF));

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event IssuerSchemaRegistered(uint256 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaRemoved(uint256 indexed issuerSchemaId, Pubkey pubkey, address signer);
    event IssuerSchemaPubkeyUpdated(uint256 indexed issuerSchemaId, Pubkey oldPubkey, Pubkey newPubkey);
    event IssuerSchemaSignerUpdated(uint256 indexed issuerSchemaId, address oldSigner, address newSigner);
    event IssuerSchemaUpdated(uint256 indexed issuerSchemaId, string oldSchemaUri, string newSchemaUri);

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract.
     */
    function initialize() public virtual initializer {
        __EIP712_init(EIP712_NAME, EIP712_VERSION);
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        _nextId = 1;
    }

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    function register(Pubkey memory pubkey, address signer)
        public
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        if (_isEmptyPubkey(pubkey)) {
            revert InvalidPubkey();
        }
        require(signer != address(0), "Registry: signer cannot be zero address");

        uint256 issuerSchemaId = _nextId;
        _idToPubkey[issuerSchemaId] = pubkey;
        _idToAddress[issuerSchemaId] = signer;
        emit IssuerSchemaRegistered(issuerSchemaId, pubkey, signer);
        _nextId = issuerSchemaId + 1;
        return issuerSchemaId;
    }

    function remove(uint256 issuerSchemaId, bytes calldata signature) public virtual onlyProxy onlyInitialized {
        Pubkey memory pubkey = _idToPubkey[issuerSchemaId];
        require(!_isEmptyPubkey(pubkey), "Registry: id not registered");
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(REMOVE_ISSUER_SCHEMA_TYPEHASH, issuerSchemaId, _nonces[issuerSchemaId]))
        );

        if (!SignatureChecker.isValidSignatureNow(_idToAddress[issuerSchemaId], messageHash, signature)) {
            revert InvalidSignature();
        }

        emit IssuerSchemaRemoved(issuerSchemaId, pubkey, _idToAddress[issuerSchemaId]);

        _nonces[issuerSchemaId]++;
        delete _idToPubkey[issuerSchemaId];
        delete _idToAddress[issuerSchemaId];
        delete idToSchemaUri[issuerSchemaId];
    }

    function updatePubkey(uint256 issuerSchemaId, Pubkey memory newPubkey, bytes calldata signature)
        public
        virtual
        onlyProxy
        onlyInitialized
    {
        Pubkey memory oldPubkey = _idToPubkey[issuerSchemaId];
        require(!_isEmptyPubkey(oldPubkey), "Registry: id not registered");

        if (_isEmptyPubkey(newPubkey)) {
            revert InvalidPubkey();
        }

        bytes32 newPubkeyHash = keccak256(abi.encode(PUBKEY_TYPEHASH, newPubkey.x, newPubkey.y));
        bytes32 oldPubkeyHash = keccak256(abi.encode(PUBKEY_TYPEHASH, oldPubkey.x, oldPubkey.y));

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_PUBKEY_TYPEHASH, issuerSchemaId, newPubkeyHash, oldPubkeyHash, _nonces[issuerSchemaId]
                )
            )
        );

        if (!SignatureChecker.isValidSignatureNow(_idToAddress[issuerSchemaId], messageHash, signature)) {
            revert InvalidSignature();
        }

        _idToPubkey[issuerSchemaId] = newPubkey;
        emit IssuerSchemaPubkeyUpdated(issuerSchemaId, oldPubkey, newPubkey);

        _nonces[issuerSchemaId]++;
    }

    function updateSigner(uint256 issuerSchemaId, address newSigner, bytes calldata signature)
        public
        virtual
        onlyProxy
        onlyInitialized
    {
        require(!_isEmptyPubkey(_idToPubkey[issuerSchemaId]), "Registry: id not registered");
        require(newSigner != address(0), "Registry: newSigner cannot be zero address");
        require(_idToAddress[issuerSchemaId] != newSigner, "Registry: newSigner is already the assigned signer");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(UPDATE_SIGNER_TYPEHASH, issuerSchemaId, newSigner, _nonces[issuerSchemaId]))
        );

        address oldSigner = _idToAddress[issuerSchemaId];

        if (!SignatureChecker.isValidSignatureNow(oldSigner, messageHash, signature)) {
            revert InvalidSignature();
        }

        _idToAddress[issuerSchemaId] = newSigner;
        emit IssuerSchemaSignerUpdated(issuerSchemaId, oldSigner, newSigner);

        _nonces[issuerSchemaId]++;
    }

    /**
     * @dev Returns the schema URI for a specific issuerSchemaId.
     * @param issuerSchemaId The issuer+schema ID.
     * @return The schema URI for the issuerSchemaId.
     */
    function getIssuerSchemaUri(uint256 issuerSchemaId)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (string memory)
    {
        return idToSchemaUri[issuerSchemaId];
    }

    /**
     * @dev Updates the schema URI for a specific issuer schema ID.
     * @param issuerSchemaId The issuer-schema ID whose schema URI will be updated.
     * @param schemaUri The new schema URI to set.
     * @param signature The signature of the issuer authorizing the update.
     */
    function updateIssuerSchemaUri(uint256 issuerSchemaId, string memory schemaUri, bytes calldata signature)
        public
        virtual
        onlyProxy
        onlyInitialized
    {
        require(issuerSchemaId != 0, "Schema ID not registered");
        require(
            keccak256(bytes(schemaUri)) != keccak256(bytes(idToSchemaUri[issuerSchemaId])),
            SchemaUriIsTheSameAsCurrentOne()
        );

        bytes32 schemaUriHash = keccak256(bytes(schemaUri));
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(UPDATE_ISSUER_SCHEMA_URI_TYPEHASH, issuerSchemaId, schemaUriHash, _nonces[issuerSchemaId])
            )
        );

        if (!SignatureChecker.isValidSignatureNow(_idToAddress[issuerSchemaId], messageHash, signature)) {
            revert InvalidSignature();
        }

        string memory oldSchemaUri = idToSchemaUri[issuerSchemaId];
        idToSchemaUri[issuerSchemaId] = schemaUri;

        emit IssuerSchemaUpdated(issuerSchemaId, oldSchemaUri, schemaUri);

        _nonces[issuerSchemaId]++;
    }

    /**
     * @dev Returns the off-chain pubkey for a specific issuerSchemaId which signs credentials and whose signature is verified on World ID ZKPs.
     * @param issuerSchemaId The issuer-schema ID whose pubkey will be returned.
     * @return The pubkey for the issuerSchemaId.
     */
    function issuerSchemaIdToPubkey(uint256 issuerSchemaId)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (Pubkey memory)
    {
        return _idToPubkey[issuerSchemaId];
    }

    /**
     * @dev Returns the on-chain signer address authorized to perform updates on a specific issuerSchemaId.
     * @param issuerSchemaId The issuer-schema ID whose signer will be returned.
     * @return The on-chain signer address for the issuerSchemaId.
     */
    function getSignerForIssuerSchemaId(uint256 issuerSchemaId)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _idToAddress[issuerSchemaId];
    }

    function nextIssuerSchemaId() public view virtual onlyProxy onlyInitialized returns (uint256) {
        return _nextId;
    }

    function nonceOf(uint256 issuerSchemaId) public view virtual onlyProxy onlyInitialized returns (uint256) {
        return _nonces[issuerSchemaId];
    }

    function _isEmptyPubkey(Pubkey memory pubkey) internal pure virtual returns (bool) {
        return pubkey.x == 0 || pubkey.y == 0;
    }

    ////////////////////////////////////////////////////////////
    //                    Upgrade Authorization               //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Authorize upgrade to a new implementation
     * @param newImplementation Address of the new implementation contract
     * @notice Only the contract owner can authorize upgrades
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    ////////////////////////////////////////////////////////////
    //                    Storage Gap                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Storage gap to allow for future upgrades without storage collisions
     * This reserves 50 storage slots for future state variables
     */
    uint256[50] private __gap;
}
