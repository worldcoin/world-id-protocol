pragma solidity ^0.8.13;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {RpRegistry} from "./RpRegistry.sol";
import {CredentialIssuerRegistry} from "./CredentialIssuerRegistry.sol";
import {AuthenticatorRegistry} from "./AuthenticatorRegistry.sol";
import {AbstractSignerPubkeyRegistry as A} from "./AbstractSignerPubkeyRegistry.sol";

contract Verifier is Ownable {
    RpRegistry public rpRegistry;
    CredentialIssuerRegistry public credentialIssuerRegistry;
    AuthenticatorRegistry public authenticatorRegistry;

    constructor(address _rpRegistry, address _credentialIssuerRegistry, address _authenticatorRegistry)
        Ownable(msg.sender)
    {
        rpRegistry = RpRegistry(_rpRegistry);
        credentialIssuerRegistry = CredentialIssuerRegistry(_credentialIssuerRegistry);
        authenticatorRegistry = AuthenticatorRegistry(_authenticatorRegistry);
    }

    function verify(
        bytes memory proof,
        uint256 rpId,
        uint256 actionId,
        uint256 credentialIssuerId,
        uint256 authenticatorRoot
    ) external view returns (bool) {
        require(authenticatorRegistry.isValidRoot(authenticatorRoot), "Invalid authenticator root");

        A.Pubkey memory rpPubkey = rpRegistry.rpIdToPubkey(rpId);
        A.Pubkey memory credentialIssuerPubkey = credentialIssuerRegistry.issuerIdToPubkey(credentialIssuerId);

        require(rpPubkey.x != 0 && rpPubkey.y != 0, "RP not registered");
        require(credentialIssuerPubkey.x != 0 && credentialIssuerPubkey.y != 0, "Credential issuer not registered");

        require(rpRegistry.isActionValid(rpId, actionId), "Action not valid");

        // TODO: Verify proof

        return true;
    }

    function updateRpRegistry(address _rpRegistry) external onlyOwner {
        rpRegistry = RpRegistry(_rpRegistry);
    }

    function updateCredentialIssuerRegistry(address _credentialIssuerRegistry) external onlyOwner {
        credentialIssuerRegistry = CredentialIssuerRegistry(_credentialIssuerRegistry);
    }

    function updateAuthenticatorRegistry(address _authenticatorRegistry) external onlyOwner {
        authenticatorRegistry = AuthenticatorRegistry(_authenticatorRegistry);
    }
}
