// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {CredentialSchemaIssuerRegistry} from "./CredentialSchemaIssuerRegistry.sol";
import {AccountRegistry} from "./AccountRegistry.sol";

contract Verifier is Ownable {
    CredentialSchemaIssuerRegistry public credentialSchemaIssuerRegistry;
    AccountRegistry public accountRegistry;

    constructor(address _credentialIssuerRegistry, address _accountRegistry) Ownable(msg.sender) {
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialIssuerRegistry);
        accountRegistry = AccountRegistry(_accountRegistry);
    }

    event AccountRegistryUpdated(address oldAccountRegistry, address newAccountRegistry);

    function verify(bytes memory /* proof */, uint256 credentialIssuerId, uint256 authenticatorRoot)
        external
        view
        returns (bool)
    {
        require(accountRegistry.isValidRoot(authenticatorRoot), "Invalid authenticator root");

        CredentialSchemaIssuerRegistry.Pubkey memory credentialIssuerPubkey =
            credentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(credentialIssuerId);
        require(credentialIssuerPubkey.x != 0 && credentialIssuerPubkey.y != 0, "Credential issuer not registered");

        // TODO: Verify proof

        return true;
    }

    function updateCredentialSchemaIssuerRegistry(address _credentialSchemaIssuerRegistry) external onlyOwner {
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialSchemaIssuerRegistry);
    }

    function updateAccountRegistry(address _accountRegistry) external onlyOwner {
        address oldAccountRegistry = address(accountRegistry);
        accountRegistry = AccountRegistry(_accountRegistry);
        emit AccountRegistryUpdated(oldAccountRegistry, _accountRegistry);
    }
}
