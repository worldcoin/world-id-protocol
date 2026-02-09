// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";
import {ICredentialSchemaIssuerRegistry} from "../src/interfaces/ICredentialSchemaIssuerRegistry.sol";

contract TestCredentialSchemaIssuerRegistry is CredentialSchemaIssuerRegistry {
    function removeUnchecked(uint64 issuerSchemaId) public {
        Pubkey memory pubkey = _idToPubkey[issuerSchemaId];
        if (_isEmptyPubkey(pubkey)) {
            revert IdNotRegistered();
        }

        address signer = _idToSigner[issuerSchemaId];

        _idToSignatureNonce[issuerSchemaId]++;
        delete _idToPubkey[issuerSchemaId];
        delete _idToSigner[issuerSchemaId];
        delete _idToSchemaUri[issuerSchemaId];

        // if we want to also delete the OPRF key, we need to have key-gens running so that there is an OPRF key to delete
        // atm this is used in tests for OPRF modules where we dont run key-gens, so we skip this step
        // _oprfKeyRegistry.deleteOprfPublicKey(uint160(issuerSchemaId));

        emit ICredentialSchemaIssuerRegistry.IssuerSchemaRemoved(issuerSchemaId, pubkey, signer);
    }
}
