// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AddressBook} from "../../src/address-book/AddressBook.sol";
import {IAddressBook} from "../../src/address-book/interfaces/IAddressBook.sol";

contract MockWorldIDVerifier {
    error ProofInvalid();
    error SignalHashMismatch();
    error ActionMismatch();
    error RpIdMismatch();

    bool public shouldRevert;

    bool public enforceExpectedSignalHash;
    uint256 public expectedSignalHash;

    bool public enforceExpectedAction;
    uint256 public expectedAction;

    bool public enforceExpectedRpId;
    uint64 public expectedRpId;

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function setExpectedSignalHash(uint256 value) external {
        expectedSignalHash = value;
        enforceExpectedSignalHash = true;
    }

    function setExpectedAction(uint256 value) external {
        expectedAction = value;
        enforceExpectedAction = true;
    }

    function setExpectedRpId(uint64 value) external {
        expectedRpId = value;
        enforceExpectedRpId = true;
    }

    function verify(
        uint256,
        uint256 action,
        uint64 rpId,
        uint256,
        uint256 signalHash,
        uint64,
        uint64,
        uint256,
        uint256[5] calldata
    ) external view {
        if (shouldRevert) revert ProofInvalid();

        if (enforceExpectedSignalHash && signalHash != expectedSignalHash) {
            revert SignalHashMismatch();
        }

        if (enforceExpectedAction && action != expectedAction) {
            revert ActionMismatch();
        }

        if (enforceExpectedRpId && rpId != expectedRpId) {
            revert RpIdMismatch();
        }
    }
}

contract AddressBookTest is Test {
    uint64 internal constant RP_ID = 42;
    uint256 internal constant ACTION = 12345;
    uint64 internal constant PERIOD_LENGTH_SECONDS = 30 days;
    uint256 internal constant USER1_PRIVATE_KEY = 0xA11CE;
    uint256 internal constant USER2_PRIVATE_KEY = 0xB0B;

    AddressBook internal addressBook;
    MockWorldIDVerifier internal verifier;

    address internal user1;
    address internal user2;

    function setUp() public {
        vm.warp(1_000_000);

        user1 = vm.addr(USER1_PRIVATE_KEY);
        user2 = vm.addr(USER2_PRIVATE_KEY);

        verifier = new MockWorldIDVerifier();
        AddressBook implementation = new AddressBook();

        bytes memory initData = abi.encodeWithSelector(
            AddressBook.initialize.selector, address(verifier), uint64(block.timestamp), PERIOD_LENGTH_SECONDS, true
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        addressBook = AddressBook(address(proxy));
    }

    function _epoch() internal pure returns (IAddressBook.EpochData memory) {
        return IAddressBook.EpochData({action: ACTION});
    }

    function _proof(uint256 nullifier) internal pure returns (IAddressBook.RegistrationProof memory) {
        uint256[5] memory zkProof;
        zkProof[0] = 1;
        zkProof[1] = 2;
        zkProof[2] = 3;
        zkProof[3] = 4;
        zkProof[4] = 5;

        return IAddressBook.RegistrationProof({
            nullifier: nullifier,
            rpId: RP_ID,
            nonce: 77,
            expiresAtMin: type(uint64).max,
            issuerSchemaId: 8,
            credentialGenesisIssuedAtMin: 0,
            zeroKnowledgeProof: zkProof
        });
    }

    function _expectVerifierInputs(uint32 period, address account) internal {
        IAddressBook.EpochData memory epoch = _epoch();
        uint256 signalHash = addressBook.computeSignalHash(period, epoch, account);

        verifier.setExpectedRpId(RP_ID);
        verifier.setExpectedAction(ACTION);
        verifier.setExpectedSignalHash(signalHash);
    }

    function testInitializeAndGetters() public view {
        assertEq(addressBook.getWorldIDVerifier(), address(verifier));
        assertEq(addressBook.getPeriodStartTimestamp(), 1_000_000);
        assertEq(addressBook.getPeriodLengthSeconds(), PERIOD_LENGTH_SECONDS);
        assertTrue(addressBook.getEnforceCurrentOrNextPeriod());
        assertEq(addressBook.getCurrentPeriod(), 0);
    }

    function testComputeEpochId() public view {
        IAddressBook.EpochData memory epoch = _epoch();
        uint32 period = addressBook.getCurrentPeriod();

        bytes32 expected = bytes32(uint256(ACTION));
        assertEq(addressBook.computeEpochId(period, epoch), expected);
    }

    function testComputeSignalHashMatchesSignalBytesHash() public view {
        IAddressBook.EpochData memory epoch = _epoch();
        uint32 period = addressBook.getCurrentPeriod();

        string memory signal = addressBook.computeSignal(period, epoch, user1);
        uint256 expected = uint256(keccak256(bytes(signal))) >> 8;
        assertEq(addressBook.computeSignalHash(period, epoch, user1), expected);
    }

    function testRegisterAndVerifyCurrentPeriod() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(period, user1);
        vm.prank(user1);
        addressBook.register(user1, period, epoch, _proof(111));

        assertTrue(addressBook.verify(epoch, user1));
        assertTrue(addressBook.isRegisteredForPeriod(period, epoch, user1));
    }

    function testVerifyRemainsTrueAfterPeriodRollover() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(period, user1);
        vm.prank(user1);
        addressBook.register(user1, period, epoch, _proof(123));

        vm.warp(block.timestamp + PERIOD_LENGTH_SECONDS);

        assertTrue(addressBook.verify(epoch, user1));
        assertTrue(addressBook.isRegisteredForPeriod(period, epoch, user1));
    }

    function testPreRegisterNextPeriod() public {
        uint32 currentPeriod = addressBook.getCurrentPeriod();
        uint32 nextPeriod = currentPeriod + 1;
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(nextPeriod, user1);
        vm.prank(user1);
        addressBook.register(user1, nextPeriod, epoch, _proof(222));

        assertTrue(addressBook.verify(epoch, user1));

        vm.warp(block.timestamp + PERIOD_LENGTH_SECONDS);

        assertTrue(addressBook.verify(epoch, user1));
    }

    function testGuardRejectsFarFuturePeriod() public {
        uint32 currentPeriod = addressBook.getCurrentPeriod();
        uint32 invalidTargetPeriod = currentPeriod + 2;
        IAddressBook.EpochData memory epoch = _epoch();

        vm.expectRevert(
            abi.encodeWithSelector(IAddressBook.InvalidTargetPeriod.selector, invalidTargetPeriod, currentPeriod)
        );
        vm.prank(user1);
        addressBook.register(user1, invalidTargetPeriod, epoch, _proof(333));
    }

    function testGuardAtMaxCurrentPeriodDoesNotPanic() public {
        MockWorldIDVerifier localVerifier = new MockWorldIDVerifier();
        AddressBook implementation = new AddressBook();

        bytes memory initData =
            abi.encodeWithSelector(AddressBook.initialize.selector, address(localVerifier), uint64(0), uint64(1), true);

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        AddressBook localAddressBook = AddressBook(address(proxy));

        vm.warp(type(uint32).max);

        IAddressBook.EpochData memory epoch = _epoch();
        uint32 currentPeriod = localAddressBook.getCurrentPeriod();
        uint32 invalidTargetPeriod = type(uint32).max - 1;

        vm.expectRevert(
            abi.encodeWithSelector(IAddressBook.InvalidTargetPeriod.selector, invalidTargetPeriod, currentPeriod)
        );
        vm.prank(user1);
        localAddressBook.register(user1, invalidTargetPeriod, epoch, _proof(123456));
    }

    function testGuardDisabledAllowsFarFuturePeriod() public {
        addressBook.setEnforceCurrentOrNextPeriod(false);

        uint32 currentPeriod = addressBook.getCurrentPeriod();
        uint32 farFuturePeriod = currentPeriod + 5;
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(farFuturePeriod, user1);
        vm.prank(user1);
        addressBook.register(user1, farFuturePeriod, epoch, _proof(444));

        assertTrue(addressBook.isRegisteredForPeriod(farFuturePeriod, epoch, user1));
        assertTrue(addressBook.verify(epoch, user1));
    }

    function testRegisterRevertsWhenExpiresBeforeTargetPeriodEnd() public {
        uint32 currentPeriod = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        uint256 epochPeriodEnd = uint256(addressBook.getPeriodStartTimestamp())
            + (uint256(currentPeriod) + 1) * uint256(addressBook.getPeriodLengthSeconds());

        IAddressBook.RegistrationProof memory proof = _proof(445);
        proof.expiresAtMin = uint64(epochPeriodEnd - 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAddressBook.ExpirationBeforeEpochEnd.selector, proof.expiresAtMin, epochPeriodEnd
            )
        );
        vm.prank(user1);
        addressBook.register(user1, currentPeriod, epoch, proof);
    }

    function testCannotReuseNullifierInSameEpoch() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(period, user1);
        vm.prank(user1);
        addressBook.register(user1, period, epoch, _proof(555));

        _expectVerifierInputs(period, user2);

        bytes32 epochId = addressBook.computeEpochId(period, epoch);
        vm.expectRevert(abi.encodeWithSelector(IAddressBook.NullifierAlreadyUsed.selector, 555, epochId));
        vm.prank(user2);
        addressBook.register(user2, period, epoch, _proof(555));
    }

    function testCannotReuseAddressInSameEpoch() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(period, user1);
        vm.prank(user1);
        addressBook.register(user1, period, epoch, _proof(666));

        bytes32 epochId = addressBook.computeEpochId(period, epoch);
        vm.expectRevert(abi.encodeWithSelector(IAddressBook.AddressAlreadyRegistered.selector, user1, epochId));
        vm.prank(user1);
        addressBook.register(user1, period, epoch, _proof(667));
    }

    function testCannotRegisterZeroAddress() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        vm.expectRevert(abi.encodeWithSelector(IAddressBook.InvalidAccount.selector));
        addressBook.register(address(0), period, epoch, _proof(777));
    }

    function testSignalHashBindingIsEnforced() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        verifier.setExpectedRpId(RP_ID);
        verifier.setExpectedAction(ACTION);

        uint256 signalForUser2 = addressBook.computeSignalHash(period, epoch, user2);
        verifier.setExpectedSignalHash(signalForUser2);

        vm.expectRevert(abi.encodeWithSelector(MockWorldIDVerifier.SignalHashMismatch.selector));
        vm.prank(user1);
        addressBook.register(user1, period, epoch, _proof(888));
    }

    function testCannotRegisterDifferentAccountWithProofBoundToAnother() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        verifier.setExpectedRpId(RP_ID);
        verifier.setExpectedAction(ACTION);

        // Simulate a proof generated with signal bound to user1.
        uint256 signalForUser1 = addressBook.computeSignalHash(period, epoch, user1);
        verifier.setExpectedSignalHash(signalForUser1);

        // Attempt to register user2 (victim) using a proof bound to user1 must fail.
        vm.expectRevert(abi.encodeWithSelector(MockWorldIDVerifier.SignalHashMismatch.selector));
        vm.prank(user2);
        addressBook.register(user2, period, epoch, _proof(889));
    }

    function testThirdPartyCanRegisterAnotherAccount() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(period, user2);

        vm.prank(user1);
        addressBook.register(user2, period, epoch, _proof(892));
        assertTrue(addressBook.verify(epoch, user2));
    }

    function testVerifierRevertBubblesUp() public {
        uint32 period = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        _expectVerifierInputs(period, user1);
        verifier.setShouldRevert(true);

        vm.expectRevert(abi.encodeWithSelector(MockWorldIDVerifier.ProofInvalid.selector));
        vm.prank(user1);
        addressBook.register(user1, period, epoch, _proof(999));
    }

    function testOwnerOnlyAdminFunctions() public {
        address nonOwner = address(0xBEEF);

        vm.prank(nonOwner);
        vm.expectRevert();
        addressBook.setEnforceCurrentOrNextPeriod(false);

        MockWorldIDVerifier newVerifier = new MockWorldIDVerifier();

        vm.prank(nonOwner);
        vm.expectRevert();
        addressBook.updateWorldIDVerifier(address(newVerifier));

        addressBook.setEnforceCurrentOrNextPeriod(false);
        assertFalse(addressBook.getEnforceCurrentOrNextPeriod());

        addressBook.updateWorldIDVerifier(address(newVerifier));
        assertEq(addressBook.getWorldIDVerifier(), address(newVerifier));
    }
}
