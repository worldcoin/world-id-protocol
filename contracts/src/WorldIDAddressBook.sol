// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";

/// @title World ID Address Book V4
/// @notice Records that an account has been verified for (rpId, issuerSchemaId) and enforces session reuse rules.
/// @dev Freshness is evaluated by the caller using `verifiedAt`; this contract does not store expirations.
contract WorldIDAddressBookV4 is Ownable2Step {
    ////////////////////////////////////////////////////////////////////////////////
    //                                   ERRORS                                   //
    ////////////////////////////////////////////////////////////////////////////////

    error InvalidConfiguration();
    error InvalidSignalBinding();
    error SessionBoundToDifferentAccount();
    error CannotRenounceOwnership();
    error InvalidSessionId();

    ////////////////////////////////////////////////////////////////////////////////
    //                                   EVENTS                                   //
    ////////////////////////////////////////////////////////////////////////////////

    event AccountVerified(address indexed account, uint64 indexed rpId, uint64 issuerSchemaId, uint256 verifiedAt);

    event RotationDelayUpdated(uint64 oldDuration, uint64 newDuration);

    event WorldIdVerifierUpdated(IWorldIDVerifier oldVerifier, IWorldIDVerifier newVerifier);

    ////////////////////////////////////////////////////////////////////////////////
    //                                   STORAGE                                  //
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice rpId => account => issuerSchemaId => verifiedAt (unix seconds)
    mapping(uint64 => mapping(address => mapping(uint64 => uint256))) public verifiedAt;

    struct Session {
        address account;
        uint64 boundAt;
    }

    /// @notice rpId => sessionId => session metadata
    mapping(uint64 => mapping(uint256 => Session)) public sessions;

    /// @notice rpId => account => sessionId
    mapping(uint64 => mapping(address => uint256)) public sessionIdByAccount;

    /// @notice Minimum delay before allowing reuse of the same (rpId, sessionId).
    uint64 public rotationDelay; // seconds

    /// @notice The verifier that validates session-based uniqueness proofs.
    IWorldIDVerifier public worldIdVerifier;

    ////////////////////////////////////////////////////////////////////////////////
    //                                CONSTRUCTOR                                 //
    ////////////////////////////////////////////////////////////////////////////////

    constructor(IWorldIDVerifier _worldIdVerifier, uint64 _rotationDelay) Ownable(msg.sender) {
        if (address(_worldIdVerifier) == address(0)) {
            revert InvalidConfiguration();
        }
        worldIdVerifier = _worldIdVerifier;
        rotationDelay = _rotationDelay;
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                                MAIN LOGIC                                  //
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Verifies an account using session-based uniqueness and records verifiedAt for (rpId, account, issuerSchemaId).
    /// @dev `signalHash` must be the left-padded 32-byte representation of the account address.
    function verifyAccount(
        uint64 rpId,
        uint256 nonce,
        uint256 signalHash,
        uint64 expiresAtMin,
        uint64 issuerSchemaId,
        uint256 credentialGenesisIssuedAtMin,
        uint256 sessionId,
        uint256[2] calldata sessionNullifier,
        uint256[5] calldata zeroKnowledgeProof
    ) external {
        if (signalHash >> 160 != 0) revert InvalidSignalBinding();
        if (msg.sender != address(uint160(signalHash))) revert InvalidSignalBinding();

        if (sessionId == 0) revert InvalidSessionId();

        // Enforce session rules (session -> account binding + rotationDelay-based reuse).
        Session storage s = sessions[rpId][sessionId];
        // s.account will be the zero address on first verification
        if (s.account != msg.sender) {
            if (s.boundAt != 0 && block.timestamp < uint256(s.boundAt) + uint256(rotationDelay)) {
                revert SessionBoundToDifferentAccount();
            }
            // handle same sessionId, different account: clear the old entry from sessionIdByAccount
            delete sessionIdByAccount[rpId][s.account]; // safe even if s.account is the zero address

            // handle same account, different sessionId: clear the old entry from sessions
            uint256 oldSessionId = sessionIdByAccount[rpId][msg.sender];
            if (oldSessionId != 0 && oldSessionId != sessionId) {
                Session storage oldS = sessions[rpId][oldSessionId];
                if (oldS.account == msg.sender) {
                    delete sessions[rpId][oldSessionId];
                }
            }
            s.account = msg.sender;
            s.boundAt = uint64(block.timestamp);
        }

        // we store the sessionId that must be reused for future verification, the RP can thus remain stateless
        // we do not enforce that accounts must use the same sessionId as this is the responsibility of the RP
        sessionIdByAccount[rpId][msg.sender] = sessionId;

        // Update verification state
        verifiedAt[rpId][msg.sender][issuerSchemaId] = block.timestamp;

        worldIdVerifier.verifySession(
            rpId,
            nonce,
            signalHash,
            expiresAtMin,
            issuerSchemaId,
            credentialGenesisIssuedAtMin,
            sessionId,
            sessionNullifier,
            zeroKnowledgeProof
        );

        emit AccountVerified(msg.sender, rpId, issuerSchemaId, block.timestamp);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                              CONFIG / ADMIN                                //
    ////////////////////////////////////////////////////////////////////////////////

    function setWorldIdVerifier(IWorldIDVerifier newVerifier) external onlyOwner {
        if (address(newVerifier) == address(0)) revert InvalidConfiguration();
        IWorldIDVerifier oldVerifier = worldIdVerifier;
        worldIdVerifier = newVerifier;
        emit WorldIdVerifierUpdated(oldVerifier, newVerifier);
    }

    function setRotationDelay(uint64 newRotationDelay) external onlyOwner {
        uint64 old = rotationDelay;
        rotationDelay = newRotationDelay;
        emit RotationDelayUpdated(old, newRotationDelay);
    }

    /// @notice Prevents the owner from renouncing ownership.
    function renounceOwnership() public view override onlyOwner {
        revert CannotRenounceOwnership();
    }
}
