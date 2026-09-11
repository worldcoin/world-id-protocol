// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, stdError} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {WorldIDBase} from "../../src/core/abstract/WorldIDBase.sol";
import {RationalDecayFeeSchedule} from "../../src/core/RationalDecayFeeSchedule.sol";
import {RpRegistry} from "../../src/core/RpRegistry.sol";
import {WorldIDFeeEscrow} from "../../src/core/WorldIDFeeEscrow.sol";
import {IFeeSchedule} from "../../src/core/interfaces/IFeeSchedule.sol";
import {IRpRegistry} from "../../src/core/interfaces/IRpRegistry.sol";
import {IWorldIDFeeEscrow} from "../../src/core/interfaces/IWorldIDFeeEscrow.sol";
import {MockERC1271Wallet} from "./Mock1271Wallet.t.sol";
import {OprfKeyRegistryMock} from "./RpRegistry.t.sol";

/// @dev A schedule that never returns a price. Models an oracle-backed schedule whose dependency is down.
contract RevertingFeeSchedule is IFeeSchedule {
    error ScheduleBroken();

    function cumulativeFee(uint256) external pure returns (uint256) {
        revert ScheduleBroken();
    }
}

/// @dev A schedule that prices correctly until toggled, then overflows. `cumulativeFee` is `view`, not `pure`,
///      so a schedule really can start failing after a channel has already settled against it.
contract FlakyFeeSchedule is IFeeSchedule {
    uint256 public immutable price;
    bool public broken;

    constructor(uint256 price_) {
        price = price_;
    }

    function setBroken(bool broken_) external {
        broken = broken_;
    }

    function cumulativeFee(uint256 count) external view returns (uint256) {
        if (broken) return count * type(uint256).max;
        return count * price;
    }
}

contract WorldIDFeeEscrowTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    uint64 internal constant RP_ID = 1;
    uint64 internal constant RP_ID_1271 = 2;
    uint256 internal constant PRICE = 1e18;

    RpRegistry internal registry;
    WorldIDFeeEscrow internal escrow;
    ERC20Mock internal token;
    /// @dev Threshold is far above every counter these tests use, so the fee stays linear at `n * PRICE`
    ///      and the arithmetic below is the same as a flat per-verification price.
    RationalDecayFeeSchedule internal schedule;
    OprfKeyRegistryMock internal oprfKeyRegistry;

    uint256 internal spendKeyPk = 0xA11CE;
    address internal spendKey;
    uint256 internal managerPk = 0xB0B;
    address internal manager;
    uint256 internal walletOwnerPk = 0xCAFE;
    address internal walletOwner;
    MockERC1271Wallet internal wallet;

    address internal payer;
    address internal collector;
    address internal stranger;

    uint64 internal deadline;

    // Cached so signing helpers make no external calls, which would otherwise consume `vm.expectRevert`.
    bytes32 internal escrowDomainSeparator;
    bytes32 internal openChannelTypehash;
    bytes32 internal paymentAuthorizationTypehash;

    function setUp() public {
        payer = makeAddr("payer");
        collector = makeAddr("collector");
        stranger = makeAddr("stranger");
        spendKey = vm.addr(spendKeyPk);
        manager = vm.addr(managerPk);
        walletOwner = vm.addr(walletOwnerPk);
        wallet = new MockERC1271Wallet(walletOwner);

        oprfKeyRegistry = new OprfKeyRegistryMock();

        RpRegistry registryImpl = new RpRegistry();
        ERC1967Proxy registryProxy = new ERC1967Proxy(
            address(registryImpl),
            abi.encodeWithSelector(RpRegistry.initialize.selector, address(0), address(0), 0, address(oprfKeyRegistry))
        );
        registry = RpRegistry(address(registryProxy));
        registry.register(RP_ID, manager, spendKey, "rp.world.org");
        registry.register(RP_ID_1271, manager, address(wallet), "wallet.world.org");

        token = new ERC20Mock();
        schedule = new RationalDecayFeeSchedule(PRICE, 1000);

        WorldIDFeeEscrow escrowImpl = new WorldIDFeeEscrow();
        ERC1967Proxy escrowProxy = new ERC1967Proxy(
            address(escrowImpl), abi.encodeWithSelector(WorldIDFeeEscrow.initialize.selector, address(registry))
        );
        escrow = WorldIDFeeEscrow(address(escrowProxy));

        escrowDomainSeparator = escrow.domainSeparatorV4();
        openChannelTypehash = escrow.OPEN_CHANNEL_TYPEHASH();
        paymentAuthorizationTypehash = escrow.PAYMENT_AUTHORIZATION_TYPEHASH();

        deadline = uint64(block.timestamp + 30 days);

        token.mint(payer, 1_000e18);
        vm.prank(payer);
        token.approve(address(escrow), type(uint256).max);
        token.mint(stranger, 1_000e18);
        vm.prank(stranger);
        token.approve(address(escrow), type(uint256).max);
    }

    ////////////////////////////////////////////////////////////
    //                        HELPERS                         //
    ////////////////////////////////////////////////////////////

    function _settings(address feeSchedule, uint32 laneCount, bytes32 salt)
        internal
        view
        returns (IWorldIDFeeEscrow.ChannelSettings memory)
    {
        return IWorldIDFeeEscrow.ChannelSettings({
            rpId: RP_ID,
            payer: payer,
            spendKey: spendKey,
            collector: collector,
            token: address(token),
            feeSchedule: feeSchedule,
            laneCount: laneCount,
            collectionDeadline: deadline,
            salt: salt
        });
    }

    function _defaultSettings() internal view returns (IWorldIDFeeEscrow.ChannelSettings memory) {
        return _settings(address(schedule), 4, bytes32(0));
    }

    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", escrowDomainSeparator, structHash));
    }

    function _signOpenChannel(uint256 pk, IWorldIDFeeEscrow.ChannelSettings memory s)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                openChannelTypehash,
                s.rpId,
                s.payer,
                s.spendKey,
                s.collector,
                s.token,
                s.feeSchedule,
                s.laneCount,
                s.collectionDeadline,
                s.salt
            )
        );
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(pk, _digest(structHash));
        return abi.encodePacked(r, sig, v);
    }

    function packNonce(uint32 lane, uint64 counter) internal pure returns (uint96) {
        return (uint96(lane) << 64) | uint96(counter);
    }

    function _paymentDigest(bytes32 channelId, uint64 rpId, uint96 channelNonce, bytes32 rpRequestDigest)
        internal
        view
        returns (bytes32)
    {
        return _digest(
            keccak256(abi.encode(paymentAuthorizationTypehash, channelId, rpId, channelNonce, rpRequestDigest))
        );
    }

    function _auth(uint256 pk, bytes32 channelId, uint64 rpId, uint32 lane, uint64 counter, bytes32 rpRequestDigest)
        internal
        view
        returns (IWorldIDFeeEscrow.PaymentAuthorization memory)
    {
        uint96 nonce = packNonce(lane, counter);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _paymentDigest(channelId, rpId, nonce, rpRequestDigest));
        return IWorldIDFeeEscrow.PaymentAuthorization({
            channelNonce: nonce, rpRequestDigest: rpRequestDigest, signature: abi.encodePacked(r, s, v)
        });
    }

    function _auth(uint256 pk, bytes32 channelId, uint32 lane, uint64 counter)
        internal
        view
        returns (IWorldIDFeeEscrow.PaymentAuthorization memory)
    {
        return _auth(pk, channelId, RP_ID, lane, counter, keccak256(abi.encodePacked("req", lane, counter)));
    }

    function _one(IWorldIDFeeEscrow.PaymentAuthorization memory a)
        internal
        pure
        returns (IWorldIDFeeEscrow.PaymentAuthorization[] memory out)
    {
        out = new IWorldIDFeeEscrow.PaymentAuthorization[](1);
        out[0] = a;
    }

    function _none() internal pure returns (IWorldIDFeeEscrow.PaymentAuthorization[] memory) {
        return new IWorldIDFeeEscrow.PaymentAuthorization[](0);
    }

    function _open(IWorldIDFeeEscrow.ChannelSettings memory s, uint256 deposit) internal returns (bytes32) {
        bytes memory sig = _signOpenChannel(spendKeyPk, s);
        vm.prank(s.payer);
        return escrow.openChannel(s, deposit, sig);
    }

    function _openDefault(uint256 deposit) internal returns (bytes32) {
        return _open(_defaultSettings(), deposit);
    }

    function _rotateSigner(address newSigner) internal {
        string memory noUpdate = registry.NO_UPDATE();
        uint256 nonce = registry.nonceOf(RP_ID);
        bytes32 structHash = keccak256(
            abi.encode(
                registry.UPDATE_RP_TYPEHASH(), RP_ID, address(0), newSigner, false, keccak256(bytes(noUpdate)), nonce
            )
        );
        bytes32 domain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(registry.EIP712_NAME())),
                keccak256(bytes(registry.EIP712_VERSION())),
                block.chainid,
                address(registry)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(managerPk, keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
        registry.updateRp(RP_ID, address(0), newSigner, false, noUpdate, nonce, abi.encodePacked(r, s, v));
    }

    function _toggleActive() internal {
        string memory noUpdate = registry.NO_UPDATE();
        uint256 nonce = registry.nonceOf(RP_ID);
        bytes32 structHash = keccak256(
            abi.encode(
                registry.UPDATE_RP_TYPEHASH(), RP_ID, address(0), address(0), true, keccak256(bytes(noUpdate)), nonce
            )
        );
        bytes32 domain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(registry.EIP712_NAME())),
                keccak256(bytes(registry.EIP712_VERSION())),
                block.chainid,
                address(registry)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(managerPk, keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
        registry.updateRp(RP_ID, address(0), address(0), true, noUpdate, nonce, abi.encodePacked(r, s, v));
    }

    ////////////////////////////////////////////////////////////
    //                      OPEN CHANNEL                      //
    ////////////////////////////////////////////////////////////

    function test_openChannel_happyPath() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes32 expectedId = escrow.computeChannelId(s);
        bytes memory sig = _signOpenChannel(spendKeyPk, s);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDFeeEscrow.ChannelOpened(expectedId, RP_ID, collector, payer, 10e18);

        vm.prank(payer);
        bytes32 channelId = escrow.openChannel(s, 10e18, sig);

        assertEq(channelId, expectedId);

        IWorldIDFeeEscrow.Channel memory c = escrow.getChannel(channelId);
        assertEq(c.balance, 10e18);
        assertEq(c.paid, 0);
        assertEq(c.settledCount, 0);
        assertEq(c.openedAt, uint64(block.timestamp));
        assertFalse(c.closed);
        assertEq(c.settings.rpId, RP_ID);
        assertEq(c.settings.payer, payer);
        assertEq(c.settings.spendKey, spendKey);
        assertEq(c.settings.collector, collector);
        assertEq(c.settings.token, address(token));
        assertEq(c.settings.feeSchedule, address(schedule));
        assertEq(c.settings.laneCount, 4);
        assertEq(c.settings.collectionDeadline, deadline);

        assertEq(token.balanceOf(address(escrow)), 10e18);
        assertEq(token.balanceOf(payer), 990e18);
    }

    function test_openChannel_revertsWhenCallerIsNotPayer() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes memory sig = _signOpenChannel(spendKeyPk, s);

        vm.prank(stranger);
        vm.expectRevert(IWorldIDFeeEscrow.NotPayer.selector);
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsOnSpendKeyMismatch() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.spendKey = vm.addr(0xDEAD);
        bytes memory sig = _signOpenChannel(0xDEAD, s);

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.SpendKeyMismatch.selector, spendKey, s.spendKey));
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsOnInvalidRpSignature() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes memory sig = _signOpenChannel(0xDEAD, s);

        vm.prank(payer);
        vm.expectRevert(IWorldIDFeeEscrow.InvalidRpSignature.selector);
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsWhenSignatureCoversDifferentSettings() public {
        IWorldIDFeeEscrow.ChannelSettings memory signed = _defaultSettings();
        bytes memory sig = _signOpenChannel(spendKeyPk, signed);

        IWorldIDFeeEscrow.ChannelSettings memory tampered = signed;
        tampered.collector = stranger;

        vm.prank(payer);
        vm.expectRevert(IWorldIDFeeEscrow.InvalidRpSignature.selector);
        escrow.openChannel(tampered, 1e18, sig);
    }

    function test_openChannel_revertsOnDuplicate() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes32 channelId = _open(s, 1e18);

        bytes memory sig = _signOpenChannel(spendKeyPk, s);
        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelAlreadyExists.selector, channelId));
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsForUnknownRp() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.rpId = 999;
        bytes memory sig = _signOpenChannel(spendKeyPk, s);

        vm.prank(payer);
        vm.expectRevert(IRpRegistry.RpIdDoesNotExist.selector);
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsForInactiveRp() public {
        _toggleActive();

        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes memory sig = _signOpenChannel(spendKeyPk, s);

        vm.prank(payer);
        vm.expectRevert(IRpRegistry.RpIdInactive.selector);
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsOnZeroLaneCount() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _settings(address(schedule), 0, bytes32(0));
        bytes memory sig = _signOpenChannel(spendKeyPk, s);

        vm.prank(payer);
        vm.expectRevert(IWorldIDFeeEscrow.ZeroLaneCount.selector);
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsOnDeadlineInPast() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.collectionDeadline = uint64(block.timestamp);
        bytes memory sig = _signOpenChannel(spendKeyPk, s);

        vm.prank(payer);
        vm.expectRevert(IWorldIDFeeEscrow.DeadlineInPast.selector);
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_revertsOnZeroAddresses() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.token = address(0);
        bytes memory sig = _signOpenChannel(spendKeyPk, s);
        vm.prank(payer);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        escrow.openChannel(s, 1e18, sig);

        s = _defaultSettings();
        s.feeSchedule = address(0);
        sig = _signOpenChannel(spendKeyPk, s);
        vm.prank(payer);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        escrow.openChannel(s, 1e18, sig);

        s = _defaultSettings();
        s.collector = address(0);
        sig = _signOpenChannel(spendKeyPk, s);
        vm.prank(payer);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        escrow.openChannel(s, 1e18, sig);

        s = _defaultSettings();
        s.spendKey = address(0);
        sig = _signOpenChannel(spendKeyPk, s);
        vm.prank(payer);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        escrow.openChannel(s, 1e18, sig);
    }

    function test_openChannel_zeroDepositThenFund() public {
        bytes32 channelId = _openDefault(0);
        assertEq(escrow.getChannel(channelId).balance, 0);

        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.ChannelFunded(channelId, payer, 5e18);
        vm.prank(payer);
        escrow.fund(channelId, 5e18);

        assertEq(escrow.getChannel(channelId).balance, 5e18);
        assertEq(token.balanceOf(address(escrow)), 5e18);
    }

    function test_fund_byAnyone() public {
        bytes32 channelId = _openDefault(0);
        vm.prank(stranger);
        escrow.fund(channelId, 7e18);
        assertEq(escrow.getChannel(channelId).balance, 7e18);
    }

    function test_fund_revertsForUnknownChannel() public {
        bytes32 channelId = keccak256("nope");
        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.fund(channelId, 1e18);
    }

    function test_channelIdDependsOnSalt() public {
        bytes32 a = _open(_settings(address(schedule), 4, bytes32(uint256(1))), 0);
        bytes32 b = _open(_settings(address(schedule), 4, bytes32(uint256(2))), 0);
        assertTrue(a != b);
    }

    ////////////////////////////////////////////////////////////
    //                         SETTLE                         //
    ////////////////////////////////////////////////////////////

    function test_settle_singleAuth() public {
        bytes32 channelId = _openDefault(10e18);

        vm.expectEmit(true, false, false, true);
        emit IWorldIDFeeEscrow.ChannelSettled(channelId, 1, PRICE, 0);
        uint256 paidNow = escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 1)));

        assertEq(paidNow, PRICE);
        assertEq(token.balanceOf(collector), PRICE);
        assertEq(escrow.getChannel(channelId).balance, 9e18);
        assertEq(escrow.getChannel(channelId).paid, PRICE);
        assertEq(escrow.laneHighWater(channelId, 0), 1);
    }

    function test_settle_onlyHighestPerLaneNeedsSubmitting() public {
        bytes32 channelId = _openDefault(10e18);

        uint256 paidNow = escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 5)));

        assertEq(paidNow, 5 * PRICE);
        assertEq(escrow.getChannel(channelId).settledCount, 5);
        assertEq(escrow.laneHighWater(channelId, 0), 5);
        assertEq(token.balanceOf(collector), 5e18);
    }

    function test_settle_multipleLanes() public {
        bytes32 channelId = _openDefault(10e18);

        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = new IWorldIDFeeEscrow.PaymentAuthorization[](2);
        auths[0] = _auth(spendKeyPk, channelId, 0, 3);
        auths[1] = _auth(spendKeyPk, channelId, 1, 2);

        uint256 paidNow = escrow.settle(channelId, auths);

        assertEq(paidNow, 5 * PRICE);
        assertEq(escrow.getChannel(channelId).settledCount, 5);
        assertEq(escrow.laneHighWater(channelId, 0), 3);
        assertEq(escrow.laneHighWater(channelId, 1), 2);
    }

    function test_settle_incrementalAcrossCalls() public {
        bytes32 channelId = _openDefault(10e18);

        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 2)));
        assertEq(escrow.getChannel(channelId).paid, 2e18);

        uint256 paidNow = escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 5)));
        assertEq(paidNow, 3e18);
        assertEq(escrow.getChannel(channelId).paid, 5e18);
        assertEq(escrow.getChannel(channelId).settledCount, 5);
    }

    function test_settle_revertsOnReplay() public {
        bytes32 channelId = _openDefault(10e18);
        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelId, 0, 3);

        escrow.settle(channelId, _one(a));

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.StaleNonce.selector, uint32(0), uint64(3), uint64(3)));
        escrow.settle(channelId, _one(a));
    }

    function test_settle_revertsOnLowerCounter() public {
        bytes32 channelId = _openDefault(10e18);
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 5)));

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.StaleNonce.selector, uint32(0), uint64(4), uint64(5)));
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 4)));
    }

    function test_settle_revertsOnDuplicateLaneWithinBatch() public {
        bytes32 channelId = _openDefault(10e18);

        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = new IWorldIDFeeEscrow.PaymentAuthorization[](2);
        auths[0] = _auth(spendKeyPk, channelId, 0, 3);
        auths[1] = _auth(spendKeyPk, channelId, 0, 3);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.StaleNonce.selector, uint32(0), uint64(3), uint64(3)));
        escrow.settle(channelId, auths);
    }

    function test_settle_revertsOnInvalidLane() public {
        bytes32 channelId = _openDefault(10e18);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidLane.selector, uint32(4), uint32(4)));
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 4, 1)));
    }

    function test_settle_revertsOnZeroCounter() public {
        bytes32 channelId = _openDefault(10e18);

        vm.expectRevert(IWorldIDFeeEscrow.ZeroCounter.selector);
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 0)));
    }

    function test_settle_revertsOnWrongSigner() public {
        bytes32 channelId = _openDefault(10e18);
        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(0xDEAD, channelId, 0, 1);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelId, _one(a));
    }

    function test_settle_revertsOnTamperedRequestDigest() public {
        bytes32 channelId = _openDefault(10e18);
        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelId, 0, 1);
        a.rpRequestDigest = keccak256("other request");

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelId, _one(a));
    }

    function test_settle_revertsWhenSignatureBoundToAnotherChannel() public {
        bytes32 channelA = _open(_settings(address(schedule), 4, bytes32(uint256(1))), 10e18);
        bytes32 channelB = _open(_settings(address(schedule), 4, bytes32(uint256(2))), 10e18);

        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelA, 0, 1);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelB, _one(a));
    }

    function test_settle_revertsWhenSignatureBoundToAnotherRpId() public {
        bytes32 channelId = _openDefault(10e18);
        IWorldIDFeeEscrow.PaymentAuthorization memory a =
            _auth(spendKeyPk, channelId, RP_ID + 1, 0, 1, keccak256("req"));

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelId, _one(a));
    }

    function test_settle_revertsAfterCollectionDeadline() public {
        bytes32 channelId = _openDefault(10e18);
        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelId, 0, 1);

        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.CollectionWindowClosed.selector, deadline));
        escrow.settle(channelId, _one(a));
    }

    function test_settle_allowedExactlyOnDeadline() public {
        bytes32 channelId = _openDefault(10e18);
        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelId, 0, 1);

        vm.warp(deadline);
        assertEq(escrow.settle(channelId, _one(a)), PRICE);
    }

    function test_settle_revertsForUnknownChannel() public {
        bytes32 channelId = keccak256("nope");
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.settle(channelId, _none());
    }

    function test_settle_underfundedThenTopUp() public {
        bytes32 channelId = _openDefault(2e18);

        vm.expectEmit(true, false, false, true);
        emit IWorldIDFeeEscrow.ChannelSettled(channelId, 5, 2e18, 3e18);
        uint256 paidNow = escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 5)));

        assertEq(paidNow, 2e18);
        assertEq(token.balanceOf(collector), 2e18);
        assertEq(escrow.getChannel(channelId).balance, 0);
        assertEq(escrow.getChannel(channelId).paid, 2e18);

        (uint256 owed, uint256 balance) = escrow.quote(channelId, 5);
        assertEq(owed, 3e18);
        assertEq(balance, 0);

        vm.prank(payer);
        escrow.fund(channelId, 3e18);

        uint256 paidLater = escrow.settle(channelId, _none());
        assertEq(paidLater, 3e18);
        assertEq(token.balanceOf(collector), 5e18);
        assertEq(escrow.getChannel(channelId).balance, 0);
        assertEq(escrow.getChannel(channelId).paid, 5e18);
    }

    function test_settle_emptyAuthsIsNoopWhenNothingOwed() public {
        bytes32 channelId = _openDefault(10e18);
        assertEq(escrow.settle(channelId, _none()), 0);
        assertEq(escrow.getChannel(channelId).balance, 10e18);
    }

    function test_settle_rationalDecayCapsTotal() public {
        // p = 1e18, T = 2  =>  maxFee = 2 * p * T = 4e18, approached but never reached.
        RationalDecayFeeSchedule decay = new RationalDecayFeeSchedule(PRICE, 2);
        assertEq(decay.maxFee(), 4e18);

        bytes32 channelId = _open(_settings(address(decay), 4, bytes32(uint256(7))), 4e18);

        // n = 2 is the linear region: 2 * 1e18.
        assertEq(escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 2))), 2e18);
        assertEq(escrow.getChannel(channelId).paid, 2e18);

        // n = 4:    2e18 + 2e18 * 2 / 4    = 3e18
        assertEq(escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 4))), 1e18);
        assertEq(escrow.getChannel(channelId).paid, 3e18);

        // n = 8:    2e18 + 2e18 * 6 / 8    = 3.5e18
        assertEq(escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 8))), 0.5e18);
        assertEq(escrow.getChannel(channelId).paid, 3.5e18);

        // n = 1000: 2e18 + 2e18 * 998 / 1000 = 3.996e18
        assertEq(escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 1000))), 0.496e18);
        assertEq(escrow.getChannel(channelId).paid, 3.996e18);
        assertEq(token.balanceOf(collector), 3.996e18);

        // A channel funded to `maxFee` can never go insolvent: owed always fits in the remaining balance.
        (uint256 owed, uint256 balance) = escrow.quote(channelId, 1e9);
        assertEq(owed, 3999996000000000);
        assertEq(balance, 4e15);
        assertLe(owed, balance);

        vm.warp(deadline + 1);
        vm.prank(payer);
        escrow.closeChannel(channelId);
        assertEq(escrow.getChannel(channelId).balance, 0);
    }

    function test_settle_usesPinnedSpendKeyAfterRegistryRotation() public {
        bytes32 channelId = _openDefault(10e18);

        _rotateSigner(vm.addr(0xFEED));
        (, address currentSigner) = registry.getOprfKeyIdAndSigner(RP_ID);
        assertEq(currentSigner, vm.addr(0xFEED));

        uint256 paidNow = escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 2)));
        assertEq(paidNow, 2e18);
    }

    function test_openAndSettle_withErc1271SpendKey() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.rpId = RP_ID_1271;
        s.spendKey = address(wallet);
        s.salt = bytes32(uint256(42));

        bytes memory sig = _signOpenChannel(walletOwnerPk, s);
        vm.prank(payer);
        bytes32 channelId = escrow.openChannel(s, 10e18, sig);

        IWorldIDFeeEscrow.PaymentAuthorization memory a =
            _auth(walletOwnerPk, channelId, RP_ID_1271, 0, 3, keccak256("req-1271"));
        assertEq(escrow.settle(channelId, _one(a)), 3e18);

        IWorldIDFeeEscrow.PaymentAuthorization memory bad =
            _auth(0xDEAD, channelId, RP_ID_1271, 1, 1, keccak256("req-bad"));
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, bad.channelNonce));
        escrow.settle(channelId, _one(bad));
    }

    ////////////////////////////////////////////////////////////
    //                         CLOSE                          //
    ////////////////////////////////////////////////////////////

    function test_close_payerBeforeDeadlineReverts() public {
        bytes32 channelId = _openDefault(10e18);

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.CollectionWindowOpen.selector, deadline));
        escrow.closeChannel(channelId);
    }

    function test_close_payerAfterDeadlineRefunds() public {
        bytes32 channelId = _openDefault(10e18);
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 2)));

        vm.warp(deadline + 1);

        vm.expectEmit(true, false, false, true);
        emit IWorldIDFeeEscrow.ChannelClosed(channelId, 0, 8e18);
        vm.prank(payer);
        escrow.closeChannel(channelId);

        assertTrue(escrow.getChannel(channelId).closed);
        assertEq(escrow.getChannel(channelId).balance, 0);
        assertEq(token.balanceOf(payer), 998e18);
        assertEq(token.balanceOf(collector), 2e18);
        assertEq(token.balanceOf(address(escrow)), 0);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelAlreadyClosed.selector, channelId));
        escrow.settle(channelId, _none());

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelAlreadyClosed.selector, channelId));
        escrow.fund(channelId, 1e18);

        vm.prank(collector);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelAlreadyClosed.selector, channelId));
        escrow.closeChannel(channelId);
    }

    function test_close_collectorAnytimePaysOutstandingFirst() public {
        bytes32 channelId = _openDefault(10e18);
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 4)));

        vm.expectEmit(true, false, false, true);
        emit IWorldIDFeeEscrow.ChannelClosed(channelId, 0, 6e18);
        vm.prank(collector);
        escrow.closeChannel(channelId);

        assertEq(token.balanceOf(collector), 4e18);
        assertEq(token.balanceOf(payer), 996e18);
    }

    function test_close_collectorCollectsUnsettledOutstanding() public {
        // Underfund, accrue outstanding, top up, then close: the outstanding fee is paid first.
        bytes32 channelId = _openDefault(2e18);
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 5)));

        vm.prank(payer);
        escrow.fund(channelId, 10e18);

        vm.expectEmit(true, false, false, true);
        emit IWorldIDFeeEscrow.ChannelClosed(channelId, 3e18, 7e18);
        vm.prank(collector);
        escrow.closeChannel(channelId);

        assertEq(token.balanceOf(collector), 5e18);
        assertEq(escrow.getChannel(channelId).paid, 5e18);
    }

    function test_close_revertsForStranger() public {
        bytes32 channelId = _openDefault(10e18);

        vm.prank(stranger);
        vm.expectRevert(IWorldIDFeeEscrow.NotPayerOrCollector.selector);
        escrow.closeChannel(channelId);
    }

    function test_close_revertsForUnknownChannel() public {
        bytes32 channelId = keccak256("nope");
        vm.prank(collector);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.closeChannel(channelId);
    }

    ////////////////////////////////////////////////////////////
    //                          VIEWS                         //
    ////////////////////////////////////////////////////////////

    function test_views() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes32 channelId = _open(s, 10e18);

        assertEq(escrow.computeChannelId(s), channelId);
        assertEq(escrow.getRpRegistry(), address(registry));
        assertEq(escrow.laneHighWater(channelId, 3), 0);

        (uint256 owed, uint256 balance) = escrow.quote(channelId, 4);
        assertEq(owed, 4e18);
        assertEq(balance, 10e18);

        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 4)));

        (owed, balance) = escrow.quote(channelId, 4);
        assertEq(owed, 0);
        assertEq(balance, 6e18);

        (owed, balance) = escrow.quote(channelId, 6);
        assertEq(owed, 2e18);
    }

    function test_quote_revertsForUnknownChannel() public {
        bytes32 channelId = keccak256("nope");
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.quote(channelId, 1);
    }

    function test_computeChannelIdIsChainAndContractBound() public view {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        assertEq(escrow.computeChannelId(s), keccak256(abi.encode(block.chainid, address(escrow), s)));
    }

    function test_implementationRejectsDirectCalls() public {
        WorldIDFeeEscrow impl = new WorldIDFeeEscrow();
        vm.expectRevert();
        impl.getRpRegistry();
    }

    function test_initializeRejectsZeroRegistry() public {
        WorldIDFeeEscrow impl = new WorldIDFeeEscrow();
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeWithSelector(WorldIDFeeEscrow.initialize.selector, address(0)));
    }

    ////////////////////////////////////////////////////////////
    //                  SCHEDULE FAILURE                      //
    ////////////////////////////////////////////////////////////

    function test_close_survivesRevertingSchedule() public {
        RevertingFeeSchedule brokenSchedule = new RevertingFeeSchedule();
        bytes32 channelId = _open(_settings(address(brokenSchedule), 4, bytes32(uint256(101))), 10e18);

        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelId, 0, 2);
        vm.expectRevert(RevertingFeeSchedule.ScheduleBroken.selector);
        escrow.settle(channelId, _one(a));

        vm.warp(deadline + 1);
        uint256 payerBefore = token.balanceOf(payer);

        vm.expectEmit(true, false, false, false);
        emit IWorldIDFeeEscrow.FeeScheduleFailed(channelId);
        vm.expectEmit(true, false, false, true);
        emit IWorldIDFeeEscrow.ChannelClosed(channelId, 0, 10e18);
        vm.prank(payer);
        escrow.closeChannel(channelId);

        assertEq(token.balanceOf(payer), payerBefore + 10e18);
        assertEq(token.balanceOf(collector), 0);
        assertTrue(escrow.getChannel(channelId).closed);
        assertEq(escrow.getChannel(channelId).balance, 0);
    }

    function test_close_survivesScheduleThatBreaksAfterSettling() public {
        FlakyFeeSchedule flaky = new FlakyFeeSchedule(PRICE);
        bytes32 channelId = _open(_settings(address(flaky), 4, bytes32(uint256(102))), 10e18);

        assertEq(escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, 0, 2))), 2e18);

        flaky.setBroken(true);

        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelId, 0, 3);
        vm.expectRevert(stdError.arithmeticError);
        escrow.settle(channelId, _one(a));

        vm.warp(deadline + 1);
        uint256 payerBefore = token.balanceOf(payer);

        vm.expectEmit(true, false, false, false);
        emit IWorldIDFeeEscrow.FeeScheduleFailed(channelId);
        vm.prank(payer);
        escrow.closeChannel(channelId);

        assertEq(token.balanceOf(payer), payerBefore + 8e18);
        assertEq(token.balanceOf(collector), 2e18);
        assertEq(escrow.getChannel(channelId).balance, 0);
    }

    function test_settle_revertsWhenScheduleOverflows() public {
        // With p = max/4 and T = 1 the tail multiplication `p * T * (n - T)` overflows from n = 6 up.
        RationalDecayFeeSchedule huge = new RationalDecayFeeSchedule(type(uint256).max / 4, 1);
        bytes32 channelId = _open(_settings(address(huge), 4, bytes32(uint256(103))), 10e18);

        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(spendKeyPk, channelId, 0, type(uint64).max);
        vm.expectRevert(stdError.arithmeticError);
        escrow.settle(channelId, _one(a));

        vm.warp(deadline + 1);
        uint256 payerBefore = token.balanceOf(payer);

        vm.prank(payer);
        escrow.closeChannel(channelId);

        assertEq(token.balanceOf(payer), payerBefore + 10e18);
        assertEq(token.balanceOf(collector), 0);
        assertEq(escrow.getChannel(channelId).balance, 0);
    }

    ////////////////////////////////////////////////////////////
    //                          FUZZ                          //
    ////////////////////////////////////////////////////////////

    function testFuzz_nonceRoundtrip(uint32 lane, uint64 counter) public pure {
        uint96 packed = packNonce(lane, counter);
        assertEq(uint32(packed >> 64), lane);
        assertEq(uint64(packed), counter);
    }

    function testFuzz_settleRejectsOutOfRangeLane(uint32 laneCount, uint32 lane) public {
        laneCount = uint32(bound(laneCount, 1, 64));
        lane = uint32(bound(lane, laneCount, type(uint32).max));

        bytes32 channelId = _open(_settings(address(schedule), laneCount, bytes32(uint256(laneCount))), 1e18);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidLane.selector, lane, laneCount));
        escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, lane, 1)));
    }

    function testFuzz_settleAcceptsInRangeLane(uint32 laneCount, uint32 lane, uint64 counter) public {
        laneCount = uint32(bound(laneCount, 1, 64));
        lane = uint32(bound(lane, 0, laneCount - 1));
        counter = uint64(bound(counter, 1, 100));

        bytes32 channelId = _open(_settings(address(schedule), laneCount, bytes32(uint256(laneCount))), 1000e18);

        uint256 paidNow = escrow.settle(channelId, _one(_auth(spendKeyPk, channelId, lane, counter)));
        assertEq(paidNow, uint256(counter) * PRICE);
        assertEq(escrow.laneHighWater(channelId, lane), counter);
    }
}
