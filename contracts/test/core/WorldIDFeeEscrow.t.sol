// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {RpRegistry} from "../../src/core/RpRegistry.sol";
import {WorldIDBase} from "../../src/core/abstract/WorldIDBase.sol";
import {WorldIDFeeEscrow} from "../../src/core/WorldIDFeeEscrow.sol";
import {IRpRegistry} from "../../src/core/interfaces/IRpRegistry.sol";
import {IWorldIDFeeEscrow} from "../../src/core/interfaces/IWorldIDFeeEscrow.sol";
import {OprfKeyRegistryMock} from "./RpRegistry.t.sol";

/// @dev Re-enters `settle` from inside the payout transfer, the only external call the escrow makes.
contract ReentrantToken is ERC20Mock {
    WorldIDFeeEscrow internal escrow;
    bytes32 internal channelId;
    bool internal entered;

    function arm(WorldIDFeeEscrow escrow_, bytes32 channelId_) external {
        escrow = escrow_;
        channelId = channelId_;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        if (address(escrow) != address(0) && !entered) {
            entered = true;
            escrow.settle(channelId, 0, new IWorldIDFeeEscrow.PaymentAuthorization[](0));
        }
        return super.transfer(to, value);
    }
}

/// @dev Adds a storage variable after the escrow's own, to prove the layout survives an upgrade.
contract WorldIDFeeEscrowV2Mock is WorldIDFeeEscrow {
    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 value) public {
        newFeature = value;
    }
}

contract WorldIDFeeEscrowTest is Test {
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint64 internal constant RP_ID = 1;
    uint256 internal constant PRICE = 1e18;
    uint64 internal constant EPOCH_LENGTH = 1 days;
    uint64 internal constant EPOCH_ZERO = 1_000_000;

    RpRegistry internal registry;
    WorldIDFeeEscrow internal escrow;
    WorldIDFeeEscrow internal escrowImpl;
    ERC1967Proxy internal escrowProxy;
    ERC20Mock internal token;
    OprfKeyRegistryMock internal oprfKeyRegistry;

    uint256 internal spendKeyPk = 0xA11CE;
    address internal spendKey;
    uint256 internal managerPk = 0xB0B;
    address internal manager;
    uint256 internal wrongPk = 0xDEAD;

    address internal collector;
    address internal funder;
    address internal stranger;

    function setUp() public {
        vm.warp(EPOCH_ZERO);

        collector = makeAddr("collector");
        funder = makeAddr("funder");
        stranger = makeAddr("stranger");
        spendKey = vm.addr(spendKeyPk);
        manager = vm.addr(managerPk);

        oprfKeyRegistry = new OprfKeyRegistryMock();
        RpRegistry registryImpl = new RpRegistry();
        ERC1967Proxy registryProxy = new ERC1967Proxy(
            address(registryImpl),
            abi.encodeWithSelector(RpRegistry.initialize.selector, address(0), address(0), 0, address(oprfKeyRegistry))
        );
        registry = RpRegistry(address(registryProxy));
        registry.register(RP_ID, manager, spendKey, "rp.world.org");

        token = new ERC20Mock();
        escrowImpl = new WorldIDFeeEscrow();
        escrowProxy = new ERC1967Proxy(
            address(escrowImpl), abi.encodeWithSelector(WorldIDFeeEscrow.initialize.selector, address(registry))
        );
        escrow = WorldIDFeeEscrow(address(escrowProxy));

        token.mint(funder, 1_000e18);
        vm.prank(funder);
        token.approve(address(escrow), type(uint256).max);
        token.mint(stranger, 1_000e18);
        vm.prank(stranger);
        token.approve(address(escrow), type(uint256).max);
    }

    ////////////////////////////////////////////////////////////
    //                        HELPERS                         //
    ////////////////////////////////////////////////////////////

    function _settings(bytes32 salt) internal view returns (IWorldIDFeeEscrow.ChannelSettings memory) {
        return IWorldIDFeeEscrow.ChannelSettings({
            rpId: RP_ID,
            spendKey: spendKey,
            collector: collector,
            token: address(token),
            pricePerUnit: PRICE,
            epochLength: EPOCH_LENGTH,
            epochZero: EPOCH_ZERO,
            salt: salt
        });
    }

    function _defaultSettings() internal view returns (IWorldIDFeeEscrow.ChannelSettings memory) {
        return _settings(bytes32(0));
    }

    function _open(IWorldIDFeeEscrow.ChannelSettings memory s) internal returns (bytes32) {
        return escrow.openChannel(s);
    }

    function _openDefault() internal returns (bytes32) {
        return escrow.openChannel(_defaultSettings());
    }

    /// @dev Opens the default channel and buys `units` of capacity in `epoch`.
    function _openAndFund(uint64 epoch, uint64 units) internal returns (bytes32 channelId) {
        channelId = _openDefault();
        vm.prank(funder);
        escrow.fund(channelId, epoch, uint256(units) * PRICE);
    }

    function _packNonce(uint32 lane, uint64 counter) internal pure returns (uint96) {
        return (uint96(lane) << 64) | uint96(counter);
    }

    function _epochEnd(uint64 epoch) internal pure returns (uint256) {
        return uint256(EPOCH_ZERO) + (uint256(epoch) + 1) * uint256(EPOCH_LENGTH);
    }

    function _auth(uint256 pk, bytes32 channelId, uint64 epoch, uint32 lane, uint64 counter)
        internal
        view
        returns (IWorldIDFeeEscrow.PaymentAuthorization memory)
    {
        uint96 nonce = _packNonce(lane, counter);
        bytes32 digest = escrow.paymentAuthorizationDigest(channelId, epoch, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return IWorldIDFeeEscrow.PaymentAuthorization({channelNonce: nonce, signature: abi.encodePacked(r, s, v)});
    }

    function _auth(bytes32 channelId, uint64 epoch, uint32 lane, uint64 counter)
        internal
        view
        returns (IWorldIDFeeEscrow.PaymentAuthorization memory)
    {
        return _auth(spendKeyPk, channelId, epoch, lane, counter);
    }

    function _batch(IWorldIDFeeEscrow.PaymentAuthorization memory a)
        internal
        pure
        returns (IWorldIDFeeEscrow.PaymentAuthorization[] memory out)
    {
        out = new IWorldIDFeeEscrow.PaymentAuthorization[](1);
        out[0] = a;
    }

    function _batch(IWorldIDFeeEscrow.PaymentAuthorization memory a, IWorldIDFeeEscrow.PaymentAuthorization memory b)
        internal
        pure
        returns (IWorldIDFeeEscrow.PaymentAuthorization[] memory out)
    {
        out = new IWorldIDFeeEscrow.PaymentAuthorization[](2);
        out[0] = a;
        out[1] = b;
    }

    function _empty() internal pure returns (IWorldIDFeeEscrow.PaymentAuthorization[] memory) {
        return new IWorldIDFeeEscrow.PaymentAuthorization[](0);
    }

    function _toggleActive() internal {
        string memory noUpdate = registry.NO_UPDATE();
        uint256 nonce = registry.nonceOf(RP_ID);
        bytes32 structHash = keccak256(
            abi.encode(
                registry.UPDATE_RP_TYPEHASH(), RP_ID, address(0), address(0), true, keccak256(bytes(noUpdate)), nonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(managerPk, keccak256(abi.encodePacked("\x19\x01", registry.domainSeparatorV4(), structHash)));
        registry.updateRp(RP_ID, address(0), address(0), true, noUpdate, nonce, abi.encodePacked(r, s, v));
    }

    function _rotateSigner(address newSigner) internal {
        string memory noUpdate = registry.NO_UPDATE();
        uint256 nonce = registry.nonceOf(RP_ID);
        bytes32 structHash = keccak256(
            abi.encode(
                registry.UPDATE_RP_TYPEHASH(), RP_ID, address(0), newSigner, false, keccak256(bytes(noUpdate)), nonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(managerPk, keccak256(abi.encodePacked("\x19\x01", registry.domainSeparatorV4(), structHash)));
        registry.updateRp(RP_ID, address(0), newSigner, false, noUpdate, nonce, abi.encodePacked(r, s, v));
    }

    ////////////////////////////////////////////////////////////
    //                      OPEN CHANNEL                      //
    ////////////////////////////////////////////////////////////

    function test_openChannel_happyPath() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes32 expectedId = escrow.computeChannelId(s);

        vm.expectEmit(true, false, false, true);
        emit IWorldIDFeeEscrow.ChannelOpened(expectedId, s);

        bytes32 channelId = escrow.openChannel(s);
        assertEq(channelId, expectedId);

        IWorldIDFeeEscrow.ChannelSettings memory stored = escrow.channelSettings(channelId);
        assertEq(stored.rpId, RP_ID);
        assertEq(stored.spendKey, spendKey);
        assertEq(stored.collector, collector);
        assertEq(stored.token, address(token));
        assertEq(stored.pricePerUnit, PRICE);
        assertEq(stored.epochLength, EPOCH_LENGTH);
        assertEq(stored.epochZero, EPOCH_ZERO);
        assertEq(stored.salt, bytes32(0));

        IWorldIDFeeEscrow.EpochState memory state = escrow.epochState(channelId, 0);
        assertEq(state.funded, 0);
        assertEq(state.settledUnits, 0);
        assertFalse(state.closed);
    }

    function test_openChannel_isPermissionless() public {
        vm.prank(stranger);
        bytes32 channelId = escrow.openChannel(_defaultSettings());
        assertEq(escrow.channelSettings(channelId).spendKey, spendKey);
    }

    function test_openChannel_revertsOnZeroSpendKey() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.spendKey = address(0);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        escrow.openChannel(s);
    }

    function test_openChannel_revertsOnZeroCollector() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.collector = address(0);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        escrow.openChannel(s);
    }

    function test_openChannel_revertsOnZeroToken() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.token = address(0);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        escrow.openChannel(s);
    }

    function test_openChannel_revertsOnZeroPrice() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.pricePerUnit = 0;
        vm.expectRevert(IWorldIDFeeEscrow.ZeroValue.selector);
        escrow.openChannel(s);
    }

    function test_openChannel_revertsOnZeroEpochLength() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.epochLength = 0;
        vm.expectRevert(IWorldIDFeeEscrow.ZeroValue.selector);
        escrow.openChannel(s);
    }

    function test_openChannel_revertsOnSpendKeyMismatch() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.spendKey = vm.addr(wrongPk);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.SpendKeyMismatch.selector, spendKey, s.spendKey));
        escrow.openChannel(s);
    }

    function test_openChannel_revertsForUnknownRp() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.rpId = 999;
        vm.expectRevert(IRpRegistry.RpIdDoesNotExist.selector);
        escrow.openChannel(s);
    }

    function test_openChannel_revertsForInactiveRp() public {
        _toggleActive();
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        vm.expectRevert(IRpRegistry.RpIdInactive.selector);
        escrow.openChannel(s);
    }

    function test_openChannel_revertsOnDuplicate() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes32 channelId = escrow.openChannel(s);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelAlreadyExists.selector, channelId));
        escrow.openChannel(s);
    }

    function test_openChannel_saltDisambiguates() public {
        bytes32 a = _open(_settings(bytes32(uint256(1))));
        bytes32 b = _open(_settings(bytes32(uint256(2))));
        assertTrue(a != b);
    }

    function test_initialize_rejectsZeroRegistry() public {
        WorldIDFeeEscrow impl = new WorldIDFeeEscrow();
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeWithSelector(WorldIDFeeEscrow.initialize.selector, address(0)));
    }

    ////////////////////////////////////////////////////////////
    //                          FUND                          //
    ////////////////////////////////////////////////////////////

    function test_fund_happyPath() public {
        bytes32 channelId = _openDefault();

        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochFunded(channelId, 0, funder, 10 * PRICE);

        vm.prank(funder);
        escrow.fund(channelId, 0, 10 * PRICE);

        assertEq(escrow.epochState(channelId, 0).funded, 10 * PRICE);
        assertEq(token.balanceOf(address(escrow)), 10 * PRICE);
        assertEq(token.balanceOf(funder), 990e18);
    }

    function test_fund_byAnyoneAndAccumulates() public {
        bytes32 channelId = _openDefault();

        vm.prank(funder);
        escrow.fund(channelId, 0, 3 * PRICE);
        vm.prank(stranger);
        escrow.fund(channelId, 0, 4 * PRICE);

        assertEq(escrow.epochState(channelId, 0).funded, 7 * PRICE);
    }

    function test_fund_futureEpochIsIndependent() public {
        bytes32 channelId = _openDefault();

        vm.prank(funder);
        escrow.fund(channelId, 5, 2 * PRICE);

        assertEq(escrow.epochState(channelId, 5).funded, 2 * PRICE);
        assertEq(escrow.epochState(channelId, 0).funded, 0);
    }

    function test_fund_revertsOnNonMultipleOfPrice() public {
        bytes32 channelId = _openDefault();

        vm.prank(funder);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.AmountNotMultipleOfPrice.selector, PRICE + 1, PRICE));
        escrow.fund(channelId, 0, PRICE + 1);
    }

    function test_fund_revertsOnZeroAmount() public {
        bytes32 channelId = _openDefault();

        vm.prank(funder);
        vm.expectRevert(IWorldIDFeeEscrow.ZeroValue.selector);
        escrow.fund(channelId, 0, 0);
    }

    function test_fund_allowedOneSecondBeforeEnd() public {
        bytes32 channelId = _openDefault();

        vm.warp(_epochEnd(0) - 1);
        vm.prank(funder);
        escrow.fund(channelId, 0, PRICE);

        assertEq(escrow.epochState(channelId, 0).funded, PRICE);
    }

    function test_fund_revertsAtEpochEnd() public {
        bytes32 channelId = _openDefault();

        vm.warp(_epochEnd(0));
        vm.prank(funder);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.EpochEnded.selector, channelId, uint64(0)));
        escrow.fund(channelId, 0, PRICE);
    }

    function test_fund_revertsAfterClose() public {
        bytes32 channelId = _openAndFund(0, 1);

        vm.warp(_epochEnd(0));
        escrow.settle(channelId, 0, _empty());

        vm.warp(_epochEnd(0) - 1);
        vm.prank(funder);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.EpochClosed.selector, channelId, uint64(0)));
        escrow.fund(channelId, 0, PRICE);
    }

    function test_fund_revertsForUnknownChannel() public {
        bytes32 channelId = keccak256("nope");
        vm.prank(funder);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.fund(channelId, 0, PRICE);
    }

    function test_fund_midEpochTopUpRaisesCapacityInSameBlock() public {
        bytes32 channelId = _openAndFund(0, 5);
        uint256 blockAtStart = block.number;
        uint256 timeAtStart = block.timestamp;

        IWorldIDFeeEscrow.PaymentAuthorization[] memory over = _batch(_auth(channelId, 0, 0, 6));
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.CapacityExceeded.selector, uint64(6), uint256(5)));
        escrow.settle(channelId, 0, over);

        vm.prank(funder);
        escrow.fund(channelId, 0, PRICE);

        escrow.settle(channelId, 0, over);

        assertEq(escrow.epochState(channelId, 0).settledUnits, 6);
        assertEq(token.balanceOf(collector), 6 * PRICE);
        assertEq(block.number, blockAtStart);
        assertEq(block.timestamp, timeAtStart);
    }

    ////////////////////////////////////////////////////////////
    //                         SETTLE                         //
    ////////////////////////////////////////////////////////////

    function test_settle_singleAuth() public {
        bytes32 channelId = _openAndFund(0, 10);

        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochSettled(channelId, 0, 1, PRICE, false);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 1)));

        assertEq(escrow.epochState(channelId, 0).settledUnits, 1);
        assertEq(escrow.laneHighWater(channelId, 0, 0), 1);
        assertEq(token.balanceOf(collector), PRICE);
    }

    function test_settle_oneAuthProvesEveryUnitOnItsLane() public {
        bytes32 channelId = _openAndFund(0, 10);

        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 5)));

        assertEq(escrow.epochState(channelId, 0).settledUnits, 5);
        assertEq(escrow.laneHighWater(channelId, 0, 0), 5);
        assertEq(token.balanceOf(collector), 5 * PRICE);
    }

    function test_settle_multipleLanes() public {
        bytes32 channelId = _openAndFund(0, 10);

        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 3), _auth(channelId, 0, 7, 2)));

        assertEq(escrow.epochState(channelId, 0).settledUnits, 5);
        assertEq(escrow.laneHighWater(channelId, 0, 0), 3);
        assertEq(escrow.laneHighWater(channelId, 0, 7), 2);
        assertEq(token.balanceOf(collector), 5 * PRICE);
    }

    function test_settle_outOfOrderBatchTakesLaneMaximum() public {
        bytes32 channelId = _openAndFund(0, 10);

        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = new IWorldIDFeeEscrow.PaymentAuthorization[](3);
        auths[0] = _auth(channelId, 0, 0, 5);
        auths[1] = _auth(channelId, 0, 0, 2);
        auths[2] = _auth(channelId, 0, 0, 4);

        escrow.settle(channelId, 0, auths);

        assertEq(escrow.laneHighWater(channelId, 0, 0), 5);
        assertEq(escrow.epochState(channelId, 0).settledUnits, 5);
        assertEq(token.balanceOf(collector), 5 * PRICE);
    }

    function test_settle_duplicateLaneEntriesRaiseTheMarkOnce() public {
        bytes32 channelId = _openAndFund(0, 10);

        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = new IWorldIDFeeEscrow.PaymentAuthorization[](3);
        auths[0] = _auth(channelId, 0, 0, 2);
        auths[1] = _auth(channelId, 0, 0, 3);
        auths[2] = _auth(channelId, 0, 0, 3);

        escrow.settle(channelId, 0, auths);

        assertEq(escrow.laneHighWater(channelId, 0, 0), 3);
        assertEq(escrow.epochState(channelId, 0).settledUnits, 3);
        assertEq(token.balanceOf(collector), 3 * PRICE);
    }

    function test_settle_incrementalAcrossCalls() public {
        bytes32 channelId = _openAndFund(0, 10);

        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 2)));
        assertEq(token.balanceOf(collector), 2 * PRICE);

        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochSettled(channelId, 0, 5, 3 * PRICE, false);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 5)));

        assertEq(token.balanceOf(collector), 5 * PRICE);
        assertEq(escrow.epochState(channelId, 0).settledUnits, 5);
    }

    function test_settle_replayedBatchPaysZero() public {
        bytes32 channelId = _openAndFund(0, 10);
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths =
            _batch(_auth(channelId, 0, 0, 3), _auth(channelId, 0, 1, 4));

        escrow.settle(channelId, 0, auths);
        assertEq(token.balanceOf(collector), 7 * PRICE);

        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochSettled(channelId, 0, 7, 0, false);
        escrow.settle(channelId, 0, auths);

        assertEq(token.balanceOf(collector), 7 * PRICE);
        assertEq(escrow.epochState(channelId, 0).settledUnits, 7);
    }

    function test_settle_staleEntryIsSkippedWithoutVerifyingItsSignature() public {
        bytes32 channelId = _openAndFund(0, 10);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 3)));

        // Signed by a key that is not the spendKey. It is below the mark, so it is never checked.
        IWorldIDFeeEscrow.PaymentAuthorization memory stale = _auth(wrongPk, channelId, 0, 0, 3);

        escrow.settle(channelId, 0, _batch(stale));

        assertEq(escrow.laneHighWater(channelId, 0, 0), 3);
        assertEq(token.balanceOf(collector), 3 * PRICE);
    }

    function test_settle_revertsOnZeroCounter() public {
        bytes32 channelId = _openAndFund(0, 10);
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(_auth(channelId, 0, 0, 0));

        vm.expectRevert(IWorldIDFeeEscrow.ZeroCounter.selector);
        escrow.settle(channelId, 0, auths);
    }

    function test_settle_revertsOnWrongSigner() public {
        bytes32 channelId = _openAndFund(0, 10);
        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(wrongPk, channelId, 0, 0, 1);
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(a);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelId, 0, auths);
    }

    function test_settle_revertsOnMalformedSignatureLength() public {
        bytes32 channelId = _openAndFund(0, 10);
        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(channelId, 0, 0, 1);
        a.signature = hex"1234";
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(a);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelId, 0, auths);
    }

    function test_settle_revertsOnMalleatedHighSSignature() public {
        bytes32 channelId = _openAndFund(0, 10);
        uint96 nonce = _packNonce(0, 1);
        bytes32 digest = escrow.paymentAuthorizationDigest(channelId, 0, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(spendKeyPk, digest);

        IWorldIDFeeEscrow.PaymentAuthorization memory malleated = IWorldIDFeeEscrow.PaymentAuthorization({
            channelNonce: nonce,
            signature: abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27))
        });
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(malleated);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, nonce));
        escrow.settle(channelId, 0, auths);
    }

    function test_settle_crossChannelReplayFails() public {
        bytes32 channelA = _open(_settings(bytes32(uint256(1))));
        bytes32 channelB = _open(_settings(bytes32(uint256(2))));
        vm.prank(funder);
        escrow.fund(channelB, 0, 10 * PRICE);

        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(channelA, 0, 0, 1);
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(a);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelB, 0, auths);
    }

    function test_settle_crossEpochReplayFails() public {
        bytes32 channelId = _openDefault();
        vm.prank(funder);
        escrow.fund(channelId, 1, 10 * PRICE);

        IWorldIDFeeEscrow.PaymentAuthorization memory a = _auth(channelId, 0, 0, 1);
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(a);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.InvalidPaymentSignature.selector, a.channelNonce));
        escrow.settle(channelId, 1, auths);
    }

    function test_settle_revertsOverCapacityAndLeavesEveryLaneUnchanged() public {
        bytes32 channelId = _openAndFund(0, 5);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 1)));

        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths =
            _batch(_auth(channelId, 0, 0, 3), _auth(channelId, 0, 1, 4));

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.CapacityExceeded.selector, uint64(7), uint256(5)));
        escrow.settle(channelId, 0, auths);

        assertEq(escrow.laneHighWater(channelId, 0, 0), 1);
        assertEq(escrow.laneHighWater(channelId, 0, 1), 0);
        assertEq(escrow.epochState(channelId, 0).settledUnits, 1);
        assertEq(token.balanceOf(collector), PRICE);
    }

    function test_settle_atExactCapacitySucceeds() public {
        bytes32 channelId = _openAndFund(0, 5);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 5)));

        assertEq(escrow.epochState(channelId, 0).settledUnits, 5);
        assertEq(token.balanceOf(collector), 5 * PRICE);
    }

    function test_settle_unfundedEpochRejectsAnyUnit() public {
        bytes32 channelId = _openDefault();
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(_auth(channelId, 0, 0, 1));

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.CapacityExceeded.selector, uint64(1), uint256(0)));
        escrow.settle(channelId, 0, auths);
    }

    function test_settle_revertsForUnknownChannel() public {
        bytes32 channelId = keccak256("nope");
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.settle(channelId, 0, _empty());
    }

    function test_settle_usesPinnedSpendKeyAfterRegistryRotation() public {
        bytes32 channelId = _openAndFund(0, 10);

        _rotateSigner(vm.addr(0xFEED));
        (, address currentSigner) = registry.getOprfKeyIdAndSigner(RP_ID);
        assertEq(currentSigner, vm.addr(0xFEED));

        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 2)));
        assertEq(token.balanceOf(collector), 2 * PRICE);
    }

    function test_settle_rejectsReentrancyFromThePayoutTransfer() public {
        ReentrantToken evil = new ReentrantToken();
        evil.mint(funder, 100e18);
        vm.prank(funder);
        evil.approve(address(escrow), type(uint256).max);

        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.token = address(evil);
        s.salt = bytes32(uint256(0xBEEF));
        bytes32 channelId = escrow.openChannel(s);

        vm.prank(funder);
        escrow.fund(channelId, 0, 10 * PRICE);
        evil.arm(escrow, channelId);

        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(_auth(channelId, 0, 0, 1));
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        escrow.settle(channelId, 0, auths);
    }

    ////////////////////////////////////////////////////////////
    //                         CLOSE                          //
    ////////////////////////////////////////////////////////////

    function test_close_notTriggeredOneSecondBeforeEnd() public {
        bytes32 channelId = _openAndFund(0, 10);

        vm.warp(_epochEnd(0) - 1);
        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochSettled(channelId, 0, 2, 2 * PRICE, false);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 2)));

        assertFalse(escrow.epochState(channelId, 0).closed);
        assertEq(token.balanceOf(collector), 2 * PRICE);
        assertEq(token.balanceOf(address(escrow)), 8 * PRICE);
    }

    function test_close_atTheBoundaryWithEmptyBatch() public {
        bytes32 channelId = _openAndFund(0, 10);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 2)));

        vm.warp(_epochEnd(0));
        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochSettled(channelId, 0, 2, 8 * PRICE, true);
        escrow.settle(channelId, 0, _empty());

        IWorldIDFeeEscrow.EpochState memory state = escrow.epochState(channelId, 0);
        assertTrue(state.closed);
        assertEq(state.settledUnits, 2);
        assertEq(token.balanceOf(collector), 10 * PRICE);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    function test_close_withABatchPaysUnitsAndRemainderInOneCall() public {
        bytes32 channelId = _openAndFund(0, 10);

        vm.warp(_epochEnd(0));
        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochSettled(channelId, 0, 4, 10 * PRICE, true);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 3), _auth(channelId, 0, 1, 1)));

        assertTrue(escrow.epochState(channelId, 0).closed);
        assertEq(escrow.epochState(channelId, 0).settledUnits, 4);
        assertEq(token.balanceOf(collector), 10 * PRICE);
    }

    function test_close_zeroRemainder() public {
        bytes32 channelId = _openAndFund(0, 3);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 3)));
        assertEq(token.balanceOf(collector), 3 * PRICE);

        vm.warp(_epochEnd(0));
        vm.expectEmit(true, true, false, true);
        emit IWorldIDFeeEscrow.EpochSettled(channelId, 0, 3, 0, true);
        escrow.settle(channelId, 0, _empty());

        assertTrue(escrow.epochState(channelId, 0).closed);
        assertEq(token.balanceOf(collector), 3 * PRICE);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    function test_close_unfundedEpochClosesAndPaysNothing() public {
        bytes32 channelId = _openDefault();

        vm.warp(_epochEnd(0));
        escrow.settle(channelId, 0, _empty());

        assertTrue(escrow.epochState(channelId, 0).closed);
        assertEq(token.balanceOf(collector), 0);
    }

    function test_close_repeatedSettleReverts() public {
        bytes32 channelId = _openAndFund(0, 4);

        vm.warp(_epochEnd(0));
        escrow.settle(channelId, 0, _empty());

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.EpochClosed.selector, channelId, uint64(0)));
        escrow.settle(channelId, 0, _empty());
    }

    function test_close_settleWithAuthsAfterCloseReverts() public {
        bytes32 channelId = _openAndFund(0, 4);
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(_auth(channelId, 0, 0, 1));

        vm.warp(_epochEnd(0));
        escrow.settle(channelId, 0, _empty());

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.EpochClosed.selector, channelId, uint64(0)));
        escrow.settle(channelId, 0, auths);
    }

    function test_close_conservationPaidEqualsFunded() public {
        bytes32 channelId = _openDefault();

        vm.prank(funder);
        escrow.fund(channelId, 0, 6 * PRICE);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 4)));
        vm.prank(stranger);
        escrow.fund(channelId, 0, 3 * PRICE);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 1, 2)));

        uint256 funded = escrow.epochState(channelId, 0).funded;
        assertEq(funded, 9 * PRICE);

        vm.warp(_epochEnd(0));
        escrow.settle(channelId, 0, _empty());

        assertEq(token.balanceOf(collector), funded);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    function test_close_leavesOtherEpochsOpen() public {
        bytes32 channelId = _openDefault();
        vm.prank(funder);
        escrow.fund(channelId, 0, 2 * PRICE);
        vm.prank(funder);
        escrow.fund(channelId, 1, 2 * PRICE);

        vm.warp(_epochEnd(0));
        escrow.settle(channelId, 0, _empty());

        assertTrue(escrow.epochState(channelId, 0).closed);
        assertFalse(escrow.epochState(channelId, 1).closed);

        escrow.settle(channelId, 1, _batch(_auth(channelId, 1, 0, 2)));
        assertEq(escrow.epochState(channelId, 1).settledUnits, 2);
        assertEq(token.balanceOf(collector), 4 * PRICE);
    }

    ////////////////////////////////////////////////////////////
    //                          VIEWS                         //
    ////////////////////////////////////////////////////////////

    function test_views() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes32 channelId = escrow.openChannel(s);

        assertEq(escrow.computeChannelId(s), channelId);
        assertEq(escrow.getRpRegistry(), address(registry));
        assertEq(escrow.laneHighWater(channelId, 0, 12), 0);
        assertEq(escrow.epochEnd(channelId, 0), _epochEnd(0));
        assertEq(escrow.epochEnd(channelId, 9), _epochEnd(9));
        assertEq(escrow.epochState(channelId, 3).funded, 0);
    }

    function test_views_revertForUnknownChannel() public {
        bytes32 channelId = keccak256("nope");
        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.channelSettings(channelId);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDFeeEscrow.ChannelNotFound.selector, channelId));
        escrow.epochEnd(channelId, 0);
    }

    function test_epochEnd_doesNotOverflowAtTheExtremes() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        s.epochLength = type(uint64).max;
        s.epochZero = type(uint64).max;
        s.salt = bytes32(uint256(0xFAB));
        bytes32 channelId = escrow.openChannel(s);

        uint64 epoch = type(uint64).max;
        uint256 expected = uint256(type(uint64).max) + (uint256(epoch) + 1) * uint256(type(uint64).max);
        assertEq(escrow.epochEnd(channelId, epoch), expected);

        // Such an epoch simply never ends, so funding it is accepted rather than reverting.
        vm.prank(funder);
        escrow.fund(channelId, epoch, PRICE);
        assertEq(escrow.epochState(channelId, epoch).funded, PRICE);
    }

    function test_paymentAuthorizationDigest_matchesLocalEip712() public view {
        bytes32 channelId = escrow.computeChannelId(_defaultSettings());
        uint96 nonce = _packNonce(3, 42);
        bytes32 expected = keccak256(
            abi.encodePacked(
                "\x19\x01",
                escrow.domainSeparatorV4(),
                keccak256(abi.encode(escrow.PAYMENT_AUTHORIZATION_TYPEHASH(), channelId, uint64(7), nonce))
            )
        );

        assertEq(escrow.paymentAuthorizationDigest(channelId, 7, nonce), expected);
    }

    function test_typehashesMatchTheSpec() public view {
        assertEq(
            escrow.CHANNEL_SETTINGS_TYPEHASH(),
            keccak256(
                "ChannelSettings(uint64 rpId,address spendKey,address collector,address token,uint256 pricePerUnit,uint64 epochLength,uint64 epochZero,bytes32 salt)"
            )
        );
        assertEq(
            escrow.PAYMENT_AUTHORIZATION_TYPEHASH(),
            keccak256("PaymentAuthorization(bytes32 channelId,uint64 epoch,uint96 channelNonce)")
        );
        assertEq(escrow.EIP712_NAME(), "WorldIDFeeEscrow");
        assertEq(escrow.EIP712_VERSION(), "1");
    }

    function testFuzz_nonceRoundtrip(uint32 lane, uint64 counter) public pure {
        uint96 packed = (uint96(lane) << 64) | uint96(counter);
        assertEq(uint32(packed >> 64), lane);
        assertEq(uint64(packed), counter);
    }

    function testFuzz_settleNeverExceedsFunding(uint64 units, uint64 counter) public {
        units = uint64(bound(units, 1, 100));
        counter = uint64(bound(counter, 1, 200));

        bytes32 channelId = _openAndFund(0, units);
        IWorldIDFeeEscrow.PaymentAuthorization[] memory auths = _batch(_auth(channelId, 0, 0, counter));

        if (counter > units) {
            vm.expectRevert(
                abi.encodeWithSelector(IWorldIDFeeEscrow.CapacityExceeded.selector, counter, uint256(units))
            );
            escrow.settle(channelId, 0, auths);
            assertEq(token.balanceOf(collector), 0);
        } else {
            escrow.settle(channelId, 0, auths);
            assertEq(token.balanceOf(collector), uint256(counter) * PRICE);
        }
        assertLe(token.balanceOf(collector), uint256(units) * PRICE);
    }

    ////////////////////////////////////////////////////////////
    //                    PROXY AND UPGRADE                   //
    ////////////////////////////////////////////////////////////

    function test_proxy_implementationRejectsDirectCalls() public {
        vm.expectRevert();
        escrowImpl.getRpRegistry();
    }

    function test_proxy_implementationCannotBeInitialized() public {
        vm.expectRevert();
        escrowImpl.initialize(address(registry));
    }

    function test_proxy_cannotInitializeTwice() public {
        vm.expectRevert();
        escrow.initialize(address(registry));
    }

    function test_proxy_ownerIsTheDeployer() public view {
        assertEq(escrow.owner(), address(this));
    }

    function test_upgrade_preservesChannelAndEpochState() public {
        bytes32 channelId = _openAndFund(0, 10);
        escrow.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 3)));

        WorldIDFeeEscrowV2Mock implV2 = new WorldIDFeeEscrowV2Mock();
        escrow.upgradeToAndCall(address(implV2), "");

        WorldIDFeeEscrowV2Mock upgraded = WorldIDFeeEscrowV2Mock(address(escrowProxy));
        assertEq(upgraded.version(), "V2");
        assertEq(upgraded.getRpRegistry(), address(registry));
        assertEq(upgraded.epochState(channelId, 0).funded, 10 * PRICE);
        assertEq(upgraded.epochState(channelId, 0).settledUnits, 3);
        assertEq(upgraded.laneHighWater(channelId, 0, 0), 3);
        assertEq(upgraded.channelSettings(channelId).pricePerUnit, PRICE);

        // The new variable sits after the escrow's own storage and starts empty.
        assertEq(upgraded.newFeature(), 0);
        upgraded.setNewFeature(42);
        assertEq(upgraded.newFeature(), 42);

        // Settlement continues from the mark the old implementation left.
        upgraded.settle(channelId, 0, _batch(_auth(channelId, 0, 0, 5)));
        assertEq(upgraded.epochState(channelId, 0).settledUnits, 5);
        assertEq(token.balanceOf(collector), 5 * PRICE);
    }

    function test_upgrade_preservesTheEip712Domain() public {
        IWorldIDFeeEscrow.ChannelSettings memory s = _defaultSettings();
        bytes32 before = escrow.computeChannelId(s);

        escrow.upgradeToAndCall(address(new WorldIDFeeEscrowV2Mock()), "");

        // The domain binds to the proxy, so ids and signatures survive an implementation swap.
        assertEq(escrow.computeChannelId(s), before);
    }

    function test_upgrade_revertsForNonOwner() public {
        WorldIDFeeEscrowV2Mock implV2 = new WorldIDFeeEscrowV2Mock();

        vm.prank(stranger);
        vm.expectRevert();
        escrow.upgradeToAndCall(address(implV2), "");
    }

    function test_upgrade_followsTwoStepOwnershipTransfer() public {
        escrow.transferOwnership(stranger);
        assertEq(escrow.pendingOwner(), stranger);
        assertEq(escrow.owner(), address(this));

        vm.prank(stranger);
        escrow.acceptOwnership();
        assertEq(escrow.owner(), stranger);

        WorldIDFeeEscrowV2Mock implV2 = new WorldIDFeeEscrowV2Mock();
        vm.expectRevert();
        escrow.upgradeToAndCall(address(implV2), "");

        vm.prank(stranger);
        escrow.upgradeToAndCall(address(implV2), "");
        assertEq(WorldIDFeeEscrowV2Mock(address(escrowProxy)).version(), "V2");
    }

    ////////////////////////////////////////////////////////////
    //                   CROSS-LANGUAGE VECTORS               //
    ////////////////////////////////////////////////////////////

    /// @dev Pins the EIP-712 encoding under a fixed domain so the Rust implementation can be checked
    ///      against it byte for byte. Inputs and outputs are written to test/vectors/fee-escrow.json.
    function test_vectors_eip712() public {
        uint256 chainId = 4801;
        address escrowAddress = address(uint160(0xFEE5C0));

        vm.chainId(chainId);

        // The EIP-712 verifyingContract is the proxy, so the proxy is what has to sit at the pinned address.
        WorldIDFeeEscrow impl = new WorldIDFeeEscrow();
        bytes memory initData = abi.encodeWithSelector(WorldIDFeeEscrow.initialize.selector, address(registry));
        deployCodeTo("ERC1967Proxy.sol:ERC1967Proxy", abi.encode(address(impl), initData), escrowAddress);
        WorldIDFeeEscrow pinned = WorldIDFeeEscrow(escrowAddress);

        IWorldIDFeeEscrow.ChannelSettings memory s = IWorldIDFeeEscrow.ChannelSettings({
            rpId: 1,
            spendKey: address(uint160(0x1111111111111111111111111111111111111111)),
            collector: address(uint160(0x2222222222222222222222222222222222222222)),
            token: address(uint160(0x3333333333333333333333333333333333333333)),
            pricePerUnit: 1e18,
            epochLength: 86_400,
            epochZero: 1_700_000_000,
            salt: bytes32(uint256(42))
        });

        uint64 epoch = 7;
        uint96 channelNonce = (uint96(3) << 64) | uint96(42);

        bytes32 channelId = pinned.computeChannelId(s);
        bytes32 paymentDigest = pinned.paymentAuthorizationDigest(channelId, epoch, channelNonce);

        assertEq(pinned.domainSeparatorV4(), 0x9f429a61ffdfe791688ddf302376b5d04006d31a9bc008b9484edcd93d262408);
        assertEq(channelId, 0x2445d3989582ca28df4e2dc71b1e21dc0f752bbc6398d7461a71f676011eb4c5);
        assertEq(paymentDigest, 0xe48a4f68fee8fe87bfd02bbb52eaad7786f3471f385b2dd9542ec87495609df7);

        string memory domain = "vectors.domain";
        vm.serializeString(domain, "name", pinned.EIP712_NAME());
        vm.serializeString(domain, "version", pinned.EIP712_VERSION());
        vm.serializeUint(domain, "chainId", chainId);
        string memory domainJson = vm.serializeAddress(domain, "verifyingContract", escrowAddress);

        string memory settings = "vectors.settings";
        vm.serializeUint(settings, "rpId", uint256(s.rpId));
        vm.serializeAddress(settings, "spendKey", s.spendKey);
        vm.serializeAddress(settings, "collector", s.collector);
        vm.serializeAddress(settings, "token", s.token);
        vm.serializeString(settings, "pricePerUnit", vm.toString(s.pricePerUnit));
        vm.serializeUint(settings, "epochLength", uint256(s.epochLength));
        vm.serializeUint(settings, "epochZero", uint256(s.epochZero));
        string memory settingsJson = vm.serializeBytes32(settings, "salt", s.salt);

        string memory payment = "vectors.paymentAuthorization";
        vm.serializeBytes32(payment, "channelId", channelId);
        vm.serializeUint(payment, "epoch", uint256(epoch));
        vm.serializeString(payment, "channelNonce", _toMinimalHex(channelNonce));
        string memory paymentJson = vm.serializeBytes32(payment, "digest", paymentDigest);

        string memory root = "vectors";
        vm.serializeString(root, "domain", domainJson);
        vm.serializeString(root, "settings", settingsJson);
        vm.serializeBytes32(root, "channelId", channelId);
        string memory json = vm.serializeString(root, "paymentAuthorization", paymentJson);

        vm.writeJson(json, "test/vectors/fee-escrow.json");
    }

    /// @dev `0x`-prefixed hex with no leading zero nibble, the form the Rust side writes a `U96` in.
    function _toMinimalHex(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0x0";

        bytes memory alphabet = "0123456789abcdef";
        uint256 nibbles;
        for (uint256 v = value; v != 0; v >>= 4) {
            nibbles++;
        }

        bytes memory out = new bytes(2 + nibbles);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i = nibbles; i > 0; i--) {
            out[1 + i] = alphabet[value & 0xF];
            value >>= 4;
        }
        return string(out);
    }

    function testFuzz_toMinimalHexRoundtrips(uint96 value) public pure {
        assertEq(vm.parseUint(_toMinimalHex(value)), uint256(value));
    }
}
