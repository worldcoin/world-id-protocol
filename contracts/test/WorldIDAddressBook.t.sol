// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {WorldIDAddressBookV4} from "../src/WorldIDAddressBook.sol";
import {IWorldIDVerifier} from "../src/interfaces/IWorldIDVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Mock verifier that tracks calls and can be configured to revert
contract MockWorldIDVerifier is IWorldIDVerifier {
    bool public shouldRevert;
    uint256 public verifySessionCallCount;

    // Track the last call parameters
    uint64 public lastRpId;
    uint256 public lastNonce;
    uint256 public lastSignalHash;
    uint64 public lastExpiresAtMin;
    uint64 public lastIssuerSchemaId;
    uint256 public lastCredentialGenesisIssuedAtMin;
    uint256 public lastSessionId;
    uint256[2] public lastSessionNullifier;
    uint256[5] public lastZeroKnowledgeProof;

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function verifySession(
        uint64,
        uint256,
        uint256,
        uint64,
        uint64,
        uint256,
        uint256,
        uint256[2] calldata,
        uint256[5] calldata
    ) external view override {
        if (shouldRevert) {
            revert("MockWorldIDVerifier: verification failed");
        }
    }

    // Non-view version to track calls (called via a wrapper)
    function trackVerifySession(
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
        verifySessionCallCount++;
        lastRpId = rpId;
        lastNonce = nonce;
        lastSignalHash = signalHash;
        lastExpiresAtMin = expiresAtMin;
        lastIssuerSchemaId = issuerSchemaId;
        lastCredentialGenesisIssuedAtMin = credentialGenesisIssuedAtMin;
        lastSessionId = sessionId;
        lastSessionNullifier = sessionNullifier;
        lastZeroKnowledgeProof = zeroKnowledgeProof;
    }

    // Stub implementations for interface compliance
    function verify(
        uint256,
        uint256,
        uint64,
        uint256,
        uint256,
        uint64,
        uint64,
        uint256,
        uint256[5] calldata
    ) external view override {}

    function _verifyProofAndSignals(
        uint256,
        uint256,
        uint64,
        uint256,
        uint256,
        uint64,
        uint64,
        uint256,
        uint256,
        uint256[5] calldata
    ) external view override {}

    function updateCredentialSchemaIssuerRegistry(address) external override {}
    function updateWorldIDRegistry(address) external override {}
    function updateOprfKeyRegistry(address) external override {}
    function updateVerifier(address) external override {}
    function updateMinExpirationThreshold(uint64) external override {}
    function getCredentialSchemaIssuerRegistry() external pure override returns (address) { return address(0); }
    function getWorldIDRegistry() external pure override returns (address) { return address(0); }
    function getOprfKeyRegistry() external pure override returns (address) { return address(0); }
    function getVerifier() external pure override returns (address) { return address(0); }
    function getMinExpirationThreshold() external pure override returns (uint256) { return 0; }
    function getTreeDepth() external pure override returns (uint256) { return 30; }
}

contract WorldIDAddressBookTest is Test {
    WorldIDAddressBookV4 public addressBook;
    MockWorldIDVerifier public mockVerifier;

    address public owner;
    address public alice;
    address public bob;
    address public charlie;

    uint64 public constant DEFAULT_ROTATION_DELAY = 7 days;
    uint64 public constant RP_ID = 12345;
    uint64 public constant ISSUER_SCHEMA_ID = 1;

    // Default proof parameters
    uint256 public constant DEFAULT_NONCE = 1;
    uint64 public constant DEFAULT_EXPIRES_AT_MIN = 1000000;
    uint256 public constant DEFAULT_CREDENTIAL_GENESIS = 0;
    uint256 public constant DEFAULT_SESSION_ID = 100;
    uint256[2] public defaultSessionNullifier = [uint256(1), uint256(2)];
    uint256[5] public defaultProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5)];

    event AccountVerified(address indexed account, uint64 indexed rpId, uint64 issuerSchemaId, uint256 verifiedAt);
    event RotationDelayUpdated(uint64 oldDuration, uint64 newDuration);
    event WorldIdVerifierUpdated(IWorldIDVerifier oldVerifier, IWorldIDVerifier newVerifier);

    function setUp() public {
        owner = address(this);
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");

        mockVerifier = new MockWorldIDVerifier();
        addressBook = new WorldIDAddressBookV4(mockVerifier, DEFAULT_ROTATION_DELAY);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                            CONSTRUCTOR TESTS                               //
    ////////////////////////////////////////////////////////////////////////////////

    function testConstructorSetsVerifier() public view {
        assertEq(address(addressBook.worldIdVerifier()), address(mockVerifier));
    }

    function testConstructorSetsRotationDelay() public view {
        assertEq(addressBook.rotationDelay(), DEFAULT_ROTATION_DELAY);
    }

    function testConstructorSetsOwner() public view {
        assertEq(addressBook.owner(), owner);
    }

    function testConstructorRevertsWithZeroVerifier() public {
        vm.expectRevert(WorldIDAddressBookV4.InvalidConfiguration.selector);
        new WorldIDAddressBookV4(IWorldIDVerifier(address(0)), DEFAULT_ROTATION_DELAY);
    }

    function testConstructorAllowsZeroRotationDelay() public {
        WorldIDAddressBookV4 book = new WorldIDAddressBookV4(mockVerifier, 0);
        assertEq(book.rotationDelay(), 0);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                          VERIFY ACCOUNT TESTS                              //
    ////////////////////////////////////////////////////////////////////////////////

    function testVerifyAccountSuccess() public {
        uint256 signalHash = uint256(uint160(alice));

        vm.expectEmit(true, true, false, true);
        emit AccountVerified(alice, RP_ID, ISSUER_SCHEMA_ID, block.timestamp);

        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        assertEq(addressBook.verifiedAt(RP_ID, alice, ISSUER_SCHEMA_ID), block.timestamp);
        assertEq(addressBook.sessionIdByAccount(RP_ID, alice), DEFAULT_SESSION_ID);

        (address sessionAccount, uint64 sessionBoundAt) = addressBook.sessions(RP_ID, DEFAULT_SESSION_ID);
        assertEq(sessionAccount, alice);
        assertEq(sessionBoundAt, uint64(block.timestamp));
    }

    function testVerifyAccountUpdatesVerifiedAtTimestamp() public {
        uint256 signalHash = uint256(uint160(alice));

        // First verification
        vm.warp(1000);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );
        assertEq(addressBook.verifiedAt(RP_ID, alice, ISSUER_SCHEMA_ID), 1000);

        // Second verification at later time
        vm.warp(2000);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );
        assertEq(addressBook.verifiedAt(RP_ID, alice, ISSUER_SCHEMA_ID), 2000);
    }

    function testVerifyAccountMultipleIssuerSchemas() public {
        uint256 signalHash = uint256(uint160(alice));
        uint64 issuerSchema1 = 1;
        uint64 issuerSchema2 = 2;

        vm.startPrank(alice);

        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            issuerSchema1,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            issuerSchema2,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        vm.stopPrank();

        assertEq(addressBook.verifiedAt(RP_ID, alice, issuerSchema1), block.timestamp);
        assertEq(addressBook.verifiedAt(RP_ID, alice, issuerSchema2), block.timestamp);
    }

    function testVerifyAccountMultipleRpIds() public {
        uint64 rpId1 = 100;
        uint64 rpId2 = 200;
        uint256 signalHash = uint256(uint160(alice));

        vm.startPrank(alice);

        addressBook.verifyAccount(
            rpId1,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        addressBook.verifyAccount(
            rpId2,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        vm.stopPrank();

        assertEq(addressBook.verifiedAt(rpId1, alice, ISSUER_SCHEMA_ID), block.timestamp);
        assertEq(addressBook.verifiedAt(rpId2, alice, ISSUER_SCHEMA_ID), block.timestamp);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                       SIGNAL BINDING VALIDATION                            //
    ////////////////////////////////////////////////////////////////////////////////

    function testVerifyAccountRevertsWhenSignalHashTooLarge() public {
        // signalHash with bits set above 160
        uint256 invalidSignalHash = uint256(uint160(alice)) | (uint256(1) << 160);

        vm.prank(alice);
        vm.expectRevert(WorldIDAddressBookV4.InvalidSignalBinding.selector);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            invalidSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );
    }

    function testVerifyAccountRevertsWhenSenderDoesNotMatchSignal() public {
        uint256 signalHash = uint256(uint160(bob)); // Signal for bob

        vm.prank(alice); // But alice is calling
        vm.expectRevert(WorldIDAddressBookV4.InvalidSignalBinding.selector);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );
    }

    function testVerifyAccountRevertsWithZeroSessionId() public {
        uint256 signalHash = uint256(uint160(alice));

        vm.prank(alice);
        vm.expectRevert(WorldIDAddressBookV4.InvalidSessionId.selector);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            0, // Invalid session ID
            defaultSessionNullifier,
            defaultProof
        );
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                         SESSION BINDING TESTS                              //
    ////////////////////////////////////////////////////////////////////////////////

    function testSessionBoundToDifferentAccountRevertsWithinRotationDelay() public {
        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice binds session
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Bob tries to use same session within rotation delay
        vm.prank(bob);
        vm.expectRevert(WorldIDAddressBookV4.SessionBoundToDifferentAccount.selector);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            bobSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID, // Same session
            defaultSessionNullifier,
            defaultProof
        );
    }

    function testSessionCanBeReusedAfterRotationDelay() public {
        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice binds session at time 1000 (non-zero to ensure boundAt check works)
        vm.warp(1000);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Warp past rotation delay
        vm.warp(1000 + DEFAULT_ROTATION_DELAY + 1);

        // Bob can now use the same session
        vm.prank(bob);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            bobSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Session is now bound to Bob
        (address sessionAccount,) = addressBook.sessions(RP_ID, DEFAULT_SESSION_ID);
        assertEq(sessionAccount, bob);
        assertEq(addressBook.sessionIdByAccount(RP_ID, bob), DEFAULT_SESSION_ID);

        // Alice's old binding should be cleared
        assertEq(addressBook.sessionIdByAccount(RP_ID, alice), 0);
    }

    function testSameAccountCanReverifyWithSameSession() public {
        uint256 signalHash = uint256(uint160(alice));

        // First verification
        vm.warp(1000);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Second verification with same session (no delay needed)
        vm.warp(1001);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        assertEq(addressBook.verifiedAt(RP_ID, alice, ISSUER_SCHEMA_ID), 1001);
    }

    function testAccountCanSwitchToNewSession() public {
        uint256 signalHash = uint256(uint160(alice));
        uint256 sessionId1 = 100;
        uint256 sessionId2 = 200;

        // First verification with session 1
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            sessionId1,
            defaultSessionNullifier,
            defaultProof
        );

        (address account1,) = addressBook.sessions(RP_ID, sessionId1);
        assertEq(account1, alice);

        // Switch to session 2
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            sessionId2,
            defaultSessionNullifier,
            defaultProof
        );

        // Old session should be cleared
        (address oldAccount,) = addressBook.sessions(RP_ID, sessionId1);
        assertEq(oldAccount, address(0));

        // New session should be bound
        (address newAccount,) = addressBook.sessions(RP_ID, sessionId2);
        assertEq(newAccount, alice);
        assertEq(addressBook.sessionIdByAccount(RP_ID, alice), sessionId2);
    }

    function testSessionBlockedOneSecondBeforeRotationDelay() public {
        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice binds session at time 1000 (non-zero to ensure boundAt check works)
        vm.warp(1000);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Warp to one second before rotation delay expires
        vm.warp(1000 + DEFAULT_ROTATION_DELAY - 1);

        // Bob should be blocked (block.timestamp < boundAt + rotationDelay)
        vm.prank(bob);
        vm.expectRevert(WorldIDAddressBookV4.SessionBoundToDifferentAccount.selector);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            bobSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );
    }

    function testSessionAllowedAtExactlyRotationDelay() public {
        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice binds session at time 1000
        vm.warp(1000);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Warp to exactly rotation delay from boundAt
        // Condition: block.timestamp < boundAt + rotationDelay
        // 1000 + 7days < 1000 + 7days => false, so reuse is allowed
        vm.warp(1000 + DEFAULT_ROTATION_DELAY);

        // Bob can use the session at exactly the rotation delay boundary
        vm.prank(bob);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            bobSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        (address sessionAccount,) = addressBook.sessions(RP_ID, DEFAULT_SESSION_ID);
        assertEq(sessionAccount, bob);
    }

    function testBoundAtZeroBypassesRotationDelay() public {
        // NOTE: This documents the behavior when boundAt is 0 (session bound at block.timestamp 0)
        // The rotation delay check is: s.boundAt != 0 && block.timestamp < s.boundAt + rotationDelay
        // If boundAt == 0, the check is bypassed, allowing immediate session reuse

        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice binds session at time 0 (boundAt = 0)
        vm.warp(0);
        vm.prank(alice);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Still at time 0, Bob can immediately reuse (boundAt check bypassed)
        vm.prank(bob);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            bobSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        (address sessionAccount,) = addressBook.sessions(RP_ID, DEFAULT_SESSION_ID);
        assertEq(sessionAccount, bob);
    }

    function testZeroRotationDelayAllowsImmediateReuse() public {
        // Deploy with zero rotation delay
        WorldIDAddressBookV4 bookNoDelay = new WorldIDAddressBookV4(mockVerifier, 0);

        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice binds session
        vm.prank(alice);
        bookNoDelay.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Bob can immediately reuse (since rotation delay is 0)
        vm.prank(bob);
        bookNoDelay.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            bobSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        (address sessionAccount,) = bookNoDelay.sessions(RP_ID, DEFAULT_SESSION_ID);
        assertEq(sessionAccount, bob);
    }

    function testSessionsAreIsolatedByRpId() public {
        uint64 rpId1 = 100;
        uint64 rpId2 = 200;
        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice uses session on rpId1
        vm.prank(alice);
        addressBook.verifyAccount(
            rpId1,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Bob can use same session ID on rpId2 (sessions are isolated by rpId)
        vm.prank(bob);
        addressBook.verifyAccount(
            rpId2,
            DEFAULT_NONCE,
            bobSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        (address account1,) = addressBook.sessions(rpId1, DEFAULT_SESSION_ID);
        (address account2,) = addressBook.sessions(rpId2, DEFAULT_SESSION_ID);
        assertEq(account1, alice);
        assertEq(account2, bob);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                            ADMIN FUNCTION TESTS                            //
    ////////////////////////////////////////////////////////////////////////////////

    function testSetWorldIdVerifierSuccess() public {
        MockWorldIDVerifier newVerifier = new MockWorldIDVerifier();

        vm.expectEmit(true, true, false, true);
        emit WorldIdVerifierUpdated(mockVerifier, newVerifier);

        addressBook.setWorldIdVerifier(newVerifier);

        assertEq(address(addressBook.worldIdVerifier()), address(newVerifier));
    }

    function testSetWorldIdVerifierRevertsWithZeroAddress() public {
        vm.expectRevert(WorldIDAddressBookV4.InvalidConfiguration.selector);
        addressBook.setWorldIdVerifier(IWorldIDVerifier(address(0)));
    }

    function testSetWorldIdVerifierRevertsForNonOwner() public {
        MockWorldIDVerifier newVerifier = new MockWorldIDVerifier();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        addressBook.setWorldIdVerifier(newVerifier);
    }

    function testSetRotationDelaySuccess() public {
        uint64 newDelay = 14 days;

        vm.expectEmit(false, false, false, true);
        emit RotationDelayUpdated(DEFAULT_ROTATION_DELAY, newDelay);

        addressBook.setRotationDelay(newDelay);

        assertEq(addressBook.rotationDelay(), newDelay);
    }

    function testSetRotationDelayToZero() public {
        addressBook.setRotationDelay(0);
        assertEq(addressBook.rotationDelay(), 0);
    }

    function testSetRotationDelayRevertsForNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        addressBook.setRotationDelay(1 days);
    }

    function testRenounceOwnershipReverts() public {
        vm.expectRevert(WorldIDAddressBookV4.CannotRenounceOwnership.selector);
        addressBook.renounceOwnership();
    }

    function testRenounceOwnershipRevertsForNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        addressBook.renounceOwnership();
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                          OWNERSHIP TRANSFER TESTS                          //
    ////////////////////////////////////////////////////////////////////////////////

    function testTransferOwnershipTwoStep() public {
        // Start transfer
        addressBook.transferOwnership(alice);
        assertEq(addressBook.owner(), owner); // Still owner
        assertEq(addressBook.pendingOwner(), alice);

        // Accept transfer
        vm.prank(alice);
        addressBook.acceptOwnership();

        assertEq(addressBook.owner(), alice);
        assertEq(addressBook.pendingOwner(), address(0));
    }

    function testOnlyPendingOwnerCanAccept() public {
        addressBook.transferOwnership(alice);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, bob));
        addressBook.acceptOwnership();
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                              FUZZ TESTS                                    //
    ////////////////////////////////////////////////////////////////////////////////

    function testFuzzVerifyAccountSignalBinding(address account) public {
        vm.assume(account != address(0));

        uint256 signalHash = uint256(uint160(account));

        vm.prank(account);
        addressBook.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        assertEq(addressBook.verifiedAt(RP_ID, account, ISSUER_SCHEMA_ID), block.timestamp);
    }

    function testFuzzSessionRotation(uint64 delay, uint256 timeDelta) public {
        vm.assume(delay > 0); // Zero delay always allows reuse
        vm.assume(delay < type(uint64).max / 2); // Avoid overflow
        vm.assume(timeDelta <= type(uint64).max);

        WorldIDAddressBookV4 book = new WorldIDAddressBookV4(mockVerifier, delay);

        uint256 aliceSignalHash = uint256(uint160(alice));
        uint256 bobSignalHash = uint256(uint160(bob));

        // Alice binds session at time 1000 (non-zero to ensure boundAt check works)
        uint256 startTime = 1000;
        vm.warp(startTime);
        vm.prank(alice);
        book.verifyAccount(
            RP_ID,
            DEFAULT_NONCE,
            aliceSignalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        // Warp relative to start time
        vm.warp(startTime + timeDelta);

        if (timeDelta < uint256(delay)) {
            // Should revert - still within rotation delay
            vm.prank(bob);
            vm.expectRevert(WorldIDAddressBookV4.SessionBoundToDifferentAccount.selector);
            book.verifyAccount(
                RP_ID,
                DEFAULT_NONCE,
                bobSignalHash,
                DEFAULT_EXPIRES_AT_MIN,
                ISSUER_SCHEMA_ID,
                DEFAULT_CREDENTIAL_GENESIS,
                DEFAULT_SESSION_ID,
                defaultSessionNullifier,
                defaultProof
            );
        } else {
            // Should succeed - past rotation delay
            vm.prank(bob);
            book.verifyAccount(
                RP_ID,
                DEFAULT_NONCE,
                bobSignalHash,
                DEFAULT_EXPIRES_AT_MIN,
                ISSUER_SCHEMA_ID,
                DEFAULT_CREDENTIAL_GENESIS,
                DEFAULT_SESSION_ID,
                defaultSessionNullifier,
                defaultProof
            );

            (address sessionAccount,) = book.sessions(RP_ID, DEFAULT_SESSION_ID);
            assertEq(sessionAccount, bob);
        }
    }

    function testFuzzMultipleRpIds(uint64 rpId1, uint64 rpId2) public {
        vm.assume(rpId1 != rpId2);

        uint256 signalHash = uint256(uint160(alice));

        vm.startPrank(alice);

        addressBook.verifyAccount(
            rpId1,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        addressBook.verifyAccount(
            rpId2,
            DEFAULT_NONCE,
            signalHash,
            DEFAULT_EXPIRES_AT_MIN,
            ISSUER_SCHEMA_ID,
            DEFAULT_CREDENTIAL_GENESIS,
            DEFAULT_SESSION_ID,
            defaultSessionNullifier,
            defaultProof
        );

        vm.stopPrank();

        assertEq(addressBook.verifiedAt(rpId1, alice, ISSUER_SCHEMA_ID), block.timestamp);
        assertEq(addressBook.verifiedAt(rpId2, alice, ISSUER_SCHEMA_ID), block.timestamp);
    }
}
