// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {RpRegistry} from "./RpRegistry.sol";
import {CredentialSchemaIssuerRegistry} from "./CredentialSchemaIssuerRegistry.sol";
import {AccountRegistry} from "./AccountRegistry.sol";
import {AbstractSignerPubkeyRegistry as A} from "./AbstractSignerPubkeyRegistry.sol";

contract Verifier is Ownable {
    RpRegistry public rpRegistry;
    CredentialSchemaIssuerRegistry public credentialSchemaIssuerRegistry;
    AccountRegistry public accountRegistry;

    constructor(address _rpRegistry, address _credentialIssuerRegistry, address _accountRegistry) Ownable(msg.sender) {
        rpRegistry = RpRegistry(_rpRegistry);
        credentialSchemaIssuerRegistry = CredentialSchemaIssuerRegistry(_credentialIssuerRegistry);
        accountRegistry = AccountRegistry(_accountRegistry);
    }

    event AccountRegistryUpdated(address oldAccountRegistry, address newAccountRegistry);

    function verify(
        bytes memory proof,
        uint256 rpId,
        uint256 actionId,
        uint256 credentialIssuerId,
        uint256 authenticatorRoot
    ) external view returns (bool) {
        require(accountRegistry.isValidRoot(authenticatorRoot), "Invalid authenticator root");

        A.Pubkey memory rpPubkey = rpRegistry.rpIdToPubkey(rpId);
        A.Pubkey memory credentialIssuerPubkey =
            credentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(credentialIssuerId);

        require(rpPubkey.x != 0 && rpPubkey.y != 0, "RP not registered");
        require(credentialIssuerPubkey.x != 0 && credentialIssuerPubkey.y != 0, "Credential issuer not registered");

        require(rpRegistry.isActionValid(rpId, actionId), "Action not valid");

        // TODO: Verify proof

        return true;
    }

    function updateRpRegistry(address _rpRegistry) external onlyOwner {
        rpRegistry = RpRegistry(_rpRegistry);
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
