// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IOprfKeyRegistry} from "lib/oprf-key-registry/src/OprfKeyRegistry.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";
import {ICredentialSchemaIssuerRegistry} from "./interfaces/ICredentialSchemaIssuerRegistry.sol";

/**
 * @title CredentialSchemaIssuerRegistry
 * @author world
 * @notice A registry of schema+issuer for credentials. Each pair has an ID which is included in each issued Credential as issuerSchemaId.
 */
contract CredentialSchemaIssuerRegistry is WorldIDBase, ICredentialSchemaIssuerRegistry {
    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    mapping(uint64 => Pubkey) private _idToPubkey;

    // Stores the on-chain signer address for each issuerSchemaId, i.e. who is authorized to perform updates on the issuerSchemaId.
    mapping(uint64 => address) private _idToAddress;

    mapping(uint64 => uint256) private _idToSignatureNonce;

    // Stores the schema URI that contains the schema definition for each issuerSchemaId.
    mapping(uint64 => string) public idToSchemaUri;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "CredentialSchemaIssuerRegistry";
    string public constant EIP712_VERSION = "1.0";

    string public constant REMOVE_ISSUER_SCHEMA_TYPEDEF = "RemoveIssuerSchema(uint64 issuerSchemaId,uint256 nonce)";
    string public constant UPDATE_PUBKEY_TYPEDEF =
        "UpdateIssuerSchemaPubkey(uint64 issuerSchemaId,Pubkey newPubkey,Pubkey oldPubkey,uint256 nonce)Pubkey(uint256 x,uint256 y)";
    string public constant UPDATE_SIGNER_TYPEDEF =
        "UpdateIssuerSchemaSigner(uint64 issuerSchemaId,address newSigner,uint256 nonce)";
    string public constant UPDATE_ISSUER_SCHEMA_URI_TYPEDEF =
        "UpdateIssuerSchemaUri(uint64 issuerSchemaId,string schemaUri,uint256 nonce)";
    string public constant PUBKEY_TYPEDEF = "Pubkey(uint256 x,uint256 y)";

    bytes32 public constant REMOVE_ISSUER_SCHEMA_TYPEHASH = keccak256(abi.encodePacked(REMOVE_ISSUER_SCHEMA_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));
    bytes32 public constant UPDATE_ISSUER_SCHEMA_URI_TYPEHASH =
        keccak256(abi.encodePacked(UPDATE_ISSUER_SCHEMA_URI_TYPEDEF));
    bytes32 public constant PUBKEY_TYPEHASH = keccak256(abi.encodePacked(PUBKEY_TYPEDEF));

    // the OPRF key registry contract, used to init OPRF key gen for blinding factors of credentials
    IOprfKeyRegistry public _oprfKeyRegistry;

    /**
     * @dev Initializes the contract.
     */
    function initialize(address feeRecipient, address feeToken, uint256 registrationFee, address oprfKeyRegistry)
        public
        virtual
        initializer
    {
        if (oprfKeyRegistry == address(0)) {
            revert ZeroAddress();
        }

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, feeRecipient, feeToken, registrationFee);
        _oprfKeyRegistry = IOprfKeyRegistry(oprfKeyRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function register(uint64 issuerSchemaId, Pubkey memory pubkey, address signer)
        public
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        if (issuerSchemaId == 0) {
            revert InvalidId();
        }

        if (_isEmptyPubkey(pubkey)) {
            revert InvalidPubkey();
        }

        if (signer == address(0)) {
            revert InvalidSigner();
        }

        Pubkey memory existingPubkey = _idToPubkey[issuerSchemaId];
        if (!_isEmptyPubkey(existingPubkey)) {
            revert IdAlreadyInUse(issuerSchemaId);
        }

        _collectFee();

        // An OPRF Key is initialized to allow authenticators to compute the blinding factor for this credential
        // NOTE that the `issuerSchemaId` must be unique across issuers and RPs (from `RpRegistry`) as the `oprfKeyId` must be unique
        // This call may revert with `AlreadySubmitted()` if the ID is taken
        _oprfKeyRegistry.initKeyGen(uint160(issuerSchemaId));

        _idToPubkey[issuerSchemaId] = pubkey;
        _idToAddress[issuerSchemaId] = signer;

        emit IssuerSchemaRegistered(issuerSchemaId, pubkey, signer, uint160(issuerSchemaId));

        return issuerSchemaId;
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function remove(uint64 issuerSchemaId, bytes calldata signature) public virtual onlyProxy onlyInitialized {
        Pubkey memory pubkey = _idToPubkey[issuerSchemaId];
        if (_isEmptyPubkey(pubkey)) {
            revert IdNotRegistered();
        }
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(REMOVE_ISSUER_SCHEMA_TYPEHASH, issuerSchemaId, _idToSignatureNonce[issuerSchemaId]))
        );

        if (!SignatureChecker.isValidSignatureNow(_idToAddress[issuerSchemaId], messageHash, signature)) {
            revert InvalidSignature();
        }

        address signer = _idToAddress[issuerSchemaId];

        _idToSignatureNonce[issuerSchemaId]++;
        delete _idToPubkey[issuerSchemaId];
        delete _idToAddress[issuerSchemaId];
        delete idToSchemaUri[issuerSchemaId];

        _oprfKeyRegistry.deleteOprfPublicKey(uint160(issuerSchemaId));

        emit IssuerSchemaRemoved(issuerSchemaId, pubkey, signer);
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function updatePubkey(uint64 issuerSchemaId, Pubkey memory newPubkey, bytes calldata signature)
        public
        virtual
        onlyProxy
        onlyInitialized
    {
        Pubkey memory oldPubkey = _idToPubkey[issuerSchemaId];
        if (_isEmptyPubkey(oldPubkey)) {
            revert IdNotRegistered();
        }

        if (_isEmptyPubkey(newPubkey)) {
            revert InvalidPubkey();
        }

        bytes32 newPubkeyHash = keccak256(abi.encode(PUBKEY_TYPEHASH, newPubkey.x, newPubkey.y));
        bytes32 oldPubkeyHash = keccak256(abi.encode(PUBKEY_TYPEHASH, oldPubkey.x, oldPubkey.y));

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_PUBKEY_TYPEHASH,
                    issuerSchemaId,
                    newPubkeyHash,
                    oldPubkeyHash,
                    _idToSignatureNonce[issuerSchemaId]
                )
            )
        );

        if (!SignatureChecker.isValidSignatureNow(_idToAddress[issuerSchemaId], messageHash, signature)) {
            revert InvalidSignature();
        }

        _idToPubkey[issuerSchemaId] = newPubkey;
        emit IssuerSchemaPubkeyUpdated(issuerSchemaId, oldPubkey, newPubkey);

        _idToSignatureNonce[issuerSchemaId]++;
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function updateSigner(uint64 issuerSchemaId, address newSigner, bytes calldata signature)
        public
        virtual
        onlyProxy
        onlyInitialized
    {
        if (_isEmptyPubkey(_idToPubkey[issuerSchemaId])) {
            revert IdNotRegistered();
        }
        if (newSigner == address(0)) {
            revert InvalidSigner();
        }
        if (_idToAddress[issuerSchemaId] == newSigner) {
            revert SignerAlreadyAssigned();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(UPDATE_SIGNER_TYPEHASH, issuerSchemaId, newSigner, _idToSignatureNonce[issuerSchemaId])
            )
        );

        address oldSigner = _idToAddress[issuerSchemaId];

        if (!SignatureChecker.isValidSignatureNow(oldSigner, messageHash, signature)) {
            revert InvalidSignature();
        }

        _idToAddress[issuerSchemaId] = newSigner;
        emit IssuerSchemaSignerUpdated(issuerSchemaId, oldSigner, newSigner);

        _idToSignatureNonce[issuerSchemaId]++;
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function getIssuerSchemaUri(uint64 issuerSchemaId)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (string memory)
    {
        return idToSchemaUri[issuerSchemaId];
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function updateIssuerSchemaUri(uint64 issuerSchemaId, string memory schemaUri, bytes calldata signature)
        public
        virtual
        onlyProxy
        onlyInitialized
    {
        if (issuerSchemaId == 0) {
            revert InvalidIssuerSchemaId();
        }
        if (keccak256(bytes(schemaUri)) == keccak256(bytes(idToSchemaUri[issuerSchemaId]))) {
            revert SchemaUriIsTheSameAsCurrentOne();
        }

        bytes32 schemaUriHash = keccak256(bytes(schemaUri));
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_ISSUER_SCHEMA_URI_TYPEHASH,
                    issuerSchemaId,
                    schemaUriHash,
                    _idToSignatureNonce[issuerSchemaId]
                )
            )
        );

        if (!SignatureChecker.isValidSignatureNow(_idToAddress[issuerSchemaId], messageHash, signature)) {
            revert InvalidSignature();
        }

        string memory oldSchemaUri = idToSchemaUri[issuerSchemaId];
        idToSchemaUri[issuerSchemaId] = schemaUri;

        emit IssuerSchemaUpdated(issuerSchemaId, oldSchemaUri, schemaUri);

        _idToSignatureNonce[issuerSchemaId]++;
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function issuerSchemaIdToPubkey(uint64 issuerSchemaId)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (Pubkey memory)
    {
        return _idToPubkey[issuerSchemaId];
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function getSignerForIssuerSchemaId(uint64 issuerSchemaId)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _idToAddress[issuerSchemaId];
    }

    /// @inheritdoc ICredentialSchemaIssuerRegistry
    function nonceOf(uint64 issuerSchemaId) public view virtual override onlyProxy onlyInitialized returns (uint256) {
        return _idToSignatureNonce[issuerSchemaId];
    }

    /**
     * @dev Checks if a pubkey is empty (has zero coordinates).
     * @param pubkey The pubkey to check.
     * @return True if the pubkey is empty, false otherwise.
     */
    function _isEmptyPubkey(Pubkey memory pubkey) internal pure virtual returns (bool) {
        return pubkey.x == 0 || pubkey.y == 0;
    }
}
