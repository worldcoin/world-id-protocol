// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {WorldIDBilling} from "../../src/core/WorldIDBilling.sol";
import {WorldIDBase} from "../../src/core/abstract/WorldIDBase.sol";
import {Verifier} from "../../src/core/Verifier.sol";
import {WorldIDVerifier} from "../../src/core/WorldIDVerifier.sol";
import {IWorldIDVerifier} from "../../src/core/interfaces/IWorldIDVerifier.sol";
import {IWorldIDBilling} from "../../src/core/interfaces/IWorldIDBilling.sol";
import {ICredentialSchemaIssuerRegistry} from "../../src/core/interfaces/ICredentialSchemaIssuerRegistry.sol";
import {IWIP101} from "../../src/core/interfaces/IWIP101.sol";

////////////////////////////////////////////////////////////
//                         MOCKS                          //
////////////////////////////////////////////////////////////

contract BillingToken is ERC20 {
    uint8 internal immutable _decimals;

    constructor(uint8 decimals_) ERC20("Worldcoin", "WLD") {
        _decimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Burns 1 wei on every transfer so the recipient receives less than requested.
contract FeeOnTransferToken is BillingToken {
    constructor() BillingToken(18) {}

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && value > 0) {
            super._update(from, address(0), 1);
            value -= 1;
        }
        super._update(from, to, value);
    }
}

/// @dev Mimics the World Chain `ChainlinkPriceFeed`: `updatedAt` is the report observation time.
contract MockPriceSource {
    int256 public answer;
    uint256 public observedAt;
    uint8 public decimals = 18;
    bool public broken;

    function set(uint256 usdPerWld_, uint256 observedAt_) external {
        answer = int256(usdPerWld_);
        observedAt = observedAt_;
    }

    function setAnswer(int256 answer_) external {
        answer = answer_;
    }

    function setDecimals(uint8 decimals_) external {
        decimals = decimals_;
    }

    function setBroken(bool broken_) external {
        broken = broken_;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        require(!broken, "PriceFeedExpired");
        return (uint80(observedAt), answer, observedAt, observedAt, uint80(observedAt));
    }
}

contract MockGroth16Verifier {
    bool public fail;

    function setFail(bool fail_) external {
        fail = fail_;
    }

    function verifyCompressedProof(uint256[4] calldata, uint256[15] calldata) external view {
        if (fail) revert Verifier.ProofInvalid();
    }
}

contract MockWorldIDRegistry {
    uint256 public validRoot;

    constructor(uint256 root) {
        validRoot = root;
    }

    function isValidRoot(uint256 root) external view returns (bool) {
        return root == validRoot;
    }

    function getTreeDepth() external pure returns (uint256) {
        return 30;
    }
}

contract MockIssuerRegistry {
    mapping(uint64 => ICredentialSchemaIssuerRegistry.Pubkey) internal _keys;

    function set(uint64 id, uint256 x, uint256 y) external {
        _keys[id] = ICredentialSchemaIssuerRegistry.Pubkey(x, y);
    }

    function issuerSchemaIdToPubkey(uint64 id) external view returns (ICredentialSchemaIssuerRegistry.Pubkey memory) {
        return _keys[id];
    }
}

contract MockOprfKeyRegistry {
    mapping(uint160 => BabyJubJub.Affine) internal _keys;

    function set(uint160 id, uint256 x, uint256 y) external {
        _keys[id] = BabyJubJub.Affine(x, y);
    }

    function getOprfPublicKey(uint160 id) external view returns (BabyJubJub.Affine memory) {
        return _keys[id];
    }
}

contract MockRpRegistry {
    error RpIdInactive();

    struct Rp {
        uint160 oprfKeyId;
        address signer;
        bool active;
    }

    mapping(uint64 => Rp) internal _rps;

    function set(uint64 rpId, uint160 oprfKeyId, address signer, bool active) external {
        _rps[rpId] = Rp(oprfKeyId, signer, active);
    }

    function getOprfKeyIdAndSigner(uint64 rpId) external view returns (uint160, address) {
        if (!_rps[rpId].active) revert RpIdInactive();
        return (_rps[rpId].oprfKeyId, _rps[rpId].signer);
    }
}

contract Wip101Signer is IWIP101 {
    enum Mode {
        Accept,
        WrongMagic,
        Revert,
        NoInterface
    }

    Mode public mode;

    function setMode(Mode mode_) external {
        mode = mode_;
    }

    function supportsInterface(bytes4 interfaceId) external view returns (bool) {
        if (mode == Mode.NoInterface) return interfaceId == type(IERC165Like).interfaceId;
        return interfaceId == type(IWIP101).interfaceId || interfaceId == type(IERC165Like).interfaceId;
    }

    function verifyRpRequest(uint8, uint256, uint64, uint64, uint256, bytes calldata) external view returns (bytes4) {
        if (mode == Mode.Revert) revert RpInvalidRequest(1);
        if (mode == Mode.WrongMagic) return 0xdeadbeef;
        return 0x35dbc8de;
    }
}

/// @dev Supports IWIP101 but returns malformed data from `verifyRpRequest`.
contract MalformedWip101Signer {
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId != 0xffffffff;
    }

    fallback() external {
        assembly {
            mstore(0, 0x35dbc8de00000000000000000000000000000000000000000000000000000000)
            return(0, 4)
        }
    }
}

interface IERC165Like {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

////////////////////////////////////////////////////////////
//                         TESTS                          //
////////////////////////////////////////////////////////////

contract WorldIDBillingTest is Test {
    uint64 constant OCT_2026 = 1790812800 + 12 hours;
    uint64 constant NOV_2026 = 1793491200 + 12 hours;
    uint64 constant DEC_2026 = 1796083200 + 12 hours;
    uint64 constant JAN_2027 = 1798761600 + 12 hours;
    uint64 constant NOW = OCT_2026 + 5 days + 12 hours;

    uint64 constant RP_ID = 42;
    uint160 constant OPRF_KEY_ID = 42;
    uint64 constant ISSUER_SCHEMA_ID = 7;
    uint256 constant ROOT = 0x1234;
    uint256 constant NULLIFIER = 0xabcdef;

    uint256 constant PRICE_PER_WORLD_ID = 0.05e18;
    uint256 constant USD_PER_WLD = 2e18;
    uint64 constant MAX_PRICE_AGE = 1 hours;
    uint64 constant REQUEST_LIFETIME = 10 minutes;
    uint64 constant MAX_REQUEST_AGE = 10 minutes;
    uint256 constant EXPIRATION_THRESHOLD = 5 hours;

    WorldIDBilling billing;
    BillingToken wld;
    MockPriceSource priceSource;
    MockGroth16Verifier groth16;
    MockWorldIDRegistry worldIDRegistry;
    MockIssuerRegistry issuerRegistry;
    MockOprfKeyRegistry oprfKeyRegistry;
    MockRpRegistry rpRegistry;
    WorldIDVerifier worldIDVerifier;

    address feeRecipient = makeAddr("feeRecipient");
    address rp = makeAddr("rp");
    address user = makeAddr("user");
    uint256 signerPk = 0xA11CE;
    address signer;
    uint256 nextNonce = 1;

    function setUp() public {
        vm.warp(NOW);
        signer = vm.addr(signerPk);

        wld = new BillingToken(18);
        priceSource = new MockPriceSource();
        priceSource.set(USD_PER_WLD, NOW);
        groth16 = new MockGroth16Verifier();
        worldIDRegistry = new MockWorldIDRegistry(ROOT);
        issuerRegistry = new MockIssuerRegistry();
        issuerRegistry.set(ISSUER_SCHEMA_ID, 11, 12);
        oprfKeyRegistry = new MockOprfKeyRegistry();
        oprfKeyRegistry.set(OPRF_KEY_ID, 21, 22);
        rpRegistry = new MockRpRegistry();
        rpRegistry.set(RP_ID, OPRF_KEY_ID, signer, true);
        bytes memory verifierInit = abi.encodeCall(
            WorldIDVerifier.initialize,
            (
                address(issuerRegistry),
                address(worldIDRegistry),
                address(oprfKeyRegistry),
                address(groth16),
                uint64(EXPIRATION_THRESHOLD)
            )
        );
        worldIDVerifier = WorldIDVerifier(address(new ERC1967Proxy(address(new WorldIDVerifier()), verifierInit)));

        billing = _deploy(address(wld));

        wld.mint(rp, 1_000_000e18);
        vm.prank(rp);
        wld.approve(address(billing), type(uint256).max);
    }

    function _deploy(address token) internal returns (WorldIDBilling) {
        WorldIDBilling implementation = new WorldIDBilling(address(worldIDVerifier), address(rpRegistry));
        bytes memory initData = abi.encodeCall(
            WorldIDBilling.initialize,
            (
                address(priceSource),
                token,
                feeRecipient,
                PRICE_PER_WORLD_ID,
                MAX_PRICE_AGE,
                MAX_REQUEST_AGE,
                REQUEST_LIFETIME
            )
        );
        return WorldIDBilling(address(new ERC1967Proxy(address(implementation), initData)));
    }

    function _scope(uint64 periodStart) internal view returns (IWorldIDBilling.BillingContext memory) {
        return IWorldIDBilling.BillingContext(block.chainid, address(billing), RP_ID, periodStart);
    }

    function _proof() internal pure returns (uint256[5] memory) {
        return [uint256(1), 2, 3, 4, ROOT];
    }

    function _authorize(IWorldIDBilling.BillingContext memory scope)
        internal
        returns (IWorldIDBilling.RegistrationAuthorization memory auth)
    {
        auth = IWorldIDBilling.RegistrationAuthorization({
            version: 1,
            oprfKeyId: OPRF_KEY_ID,
            nonce: nextNonce++,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + REQUEST_LIFETIME),
            signature: "",
            wip101Data: ""
        });
        auth.signature = _sign(auth, billing.getBillingAction(scope));
    }

    function _sign(IWorldIDBilling.RegistrationAuthorization memory auth, uint256 action)
        internal
        view
        returns (bytes memory)
    {
        bytes memory message = abi.encodePacked(uint8(1), auth.nonce, auth.createdAt, auth.expiresAt, action);
        assertEq(message.length, 81);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, MessageHashUtils.toEthSignedMessageHash(message));
        return abi.encodePacked(r, s, v);
    }

    function _buy(uint64 periodStart, uint256 amount) internal {
        vm.prank(rp);
        billing.purchaseCapacity(_scope(periodStart), amount, type(uint256).max);
    }

    function _register(IWorldIDBilling.RegistrationAuthorization memory auth, uint256 nullifier)
        internal
        returns (bool)
    {
        vm.prank(user);
        return billing.register(_scope(OCT_2026), auth, ISSUER_SCHEMA_ID, NOW, nullifier, _proof());
    }

    ////////////////////////////////////////////////////////////
    //                        PERIODS                         //
    ////////////////////////////////////////////////////////////

    function test_GetBillingPeriod_KnownDates() public view {
        _assertPeriod(NOW, OCT_2026, NOV_2026);
        _assertPeriod(OCT_2026, OCT_2026, NOV_2026);
        _assertPeriod(NOV_2026 - 1, OCT_2026, NOV_2026);
        _assertPeriod(DEC_2026 + 30 days, DEC_2026, JAN_2027);
        _assertPeriod(1709164800, 1706745600 + 12 hours, 1709251200 + 12 hours); // 2024-02-29 (leap day)
        _assertPeriod(1832976000 + 28 days, 1832976000 + 12 hours, 1835481600 + 12 hours); // 2028-02-29
        _assertPeriod(NOV_2026 - 12 hours, OCT_2026, NOV_2026);
        _assertPeriod(NOV_2026, NOV_2026, DEC_2026);
    }

    function _assertPeriod(uint64 timestamp, uint64 start, uint64 end) internal view {
        (uint64 periodStart, uint64 periodEnd) = billing.getBillingPeriod(timestamp);
        assertEq(periodStart, start, "start");
        assertEq(periodEnd, end, "end");
    }

    function testFuzz_GetBillingPeriod_ContainsTimestamp(uint64 timestamp) public view {
        timestamp = uint64(bound(timestamp, 12 hours, 253402300799)); // through 9999-12-31
        (uint64 periodStart, uint64 periodEnd) = billing.getBillingPeriod(timestamp);
        assertLe(periodStart, timestamp);
        assertGt(periodEnd, timestamp);
        assertGe(periodEnd - periodStart, 28 days);
        assertLe(periodEnd - periodStart, 31 days);
        assertEq(periodStart % 1 days, 12 hours);
        (uint64 again,) = billing.getBillingPeriod(periodStart);
        assertEq(again, periodStart, "canonical");
        (uint64 next,) = billing.getBillingPeriod(periodEnd);
        assertEq(next, periodEnd, "next canonical");
    }

    function test_BillingAction_MatchesSpec() public view {
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        uint256 expected = uint256(
            keccak256(abi.encode("world-id-billing-v1", block.chainid, address(billing), RP_ID, OCT_2026))
        ) >> 8;
        assertEq(billing.getBillingAction(scope), expected);
        assertEq(expected >> 248, 0, "uniqueness prefix");
    }

    function test_GetBillingPeriod_RejectsUnrepresentablePeriod() public {
        vm.expectRevert(IWorldIDBilling.BillingPeriodBeforeUnixEpoch.selector);
        billing.getBillingPeriod(12 hours - 1);
        _assertPeriod(12 hours, 12 hours, 2678400 + 12 hours);
    }

    function test_Quote_ProratesUntilAoeMonthEnd() public {
        vm.warp(NOV_2026 - 12 hours);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        assertEq(billing.quotePurchase(_scope(OCT_2026), 10), 4032258064516130);
        assertEq(billing.quotePurchase(_scope(NOV_2026), 10), 0.25e18);
        _buy(OCT_2026, 10);
        assertEq(wld.balanceOf(feeRecipient), 4032258064516130);
    }

    function test_Register_OverlapBoundaries() public {
        _buy(OCT_2026, 1);
        _buy(NOV_2026, 2);
        IWorldIDBilling.BillingContext memory october = _scope(OCT_2026);
        IWorldIDBilling.BillingContext memory november = _scope(NOV_2026);

        vm.warp(NOV_2026 - 26 hours - 1);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(november);
        vm.expectRevert(IWorldIDBilling.PeriodNotCurrent.selector);
        billing.register(november, auth, ISSUER_SCHEMA_ID, uint64(vm.getBlockTimestamp()), NULLIFIER, _proof());

        vm.warp(NOV_2026 - 26 hours);
        auth = _authorize(november);
        assertTrue(
            billing.register(november, auth, ISSUER_SCHEMA_ID, uint64(vm.getBlockTimestamp()), NULLIFIER, _proof())
        );

        vm.warp(NOV_2026 - 1);
        auth = _authorize(october);
        assertTrue(
            billing.register(october, auth, ISSUER_SCHEMA_ID, uint64(vm.getBlockTimestamp()), NULLIFIER + 2, _proof())
        );
        assertTrue(billing.isRegistered(NULLIFIER + 2));
        assertTrue(billing.isRegistered(NULLIFIER));

        vm.warp(NOV_2026);
        auth = _authorize(october);
        vm.expectRevert(IWorldIDBilling.PeriodNotCurrent.selector);
        billing.register(october, auth, ISSUER_SCHEMA_ID, uint64(vm.getBlockTimestamp()), NULLIFIER, _proof());
        auth = _authorize(november);
        assertTrue(
            billing.register(november, auth, ISSUER_SCHEMA_ID, uint64(vm.getBlockTimestamp()), NULLIFIER + 1, _proof())
        );
    }

    function test_RegisterMany_OverlapAcrossYearBoundary() public {
        vm.warp(DEC_2026 + 10 days);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        _buy(DEC_2026, 1);
        _buy(JAN_2027, 1);
        vm.warp(JAN_2027 - 12 hours);

        IWorldIDBilling.Registration[] memory entries = new IWorldIDBilling.Registration[](1);
        IWorldIDBilling.BillingContext memory december = _scope(DEC_2026);
        entries[0] = _entry(december, NULLIFIER);
        entries[0].expiresAtMin = uint64(vm.getBlockTimestamp());
        assertTrue(billing.registerMany(december, entries)[0]);

        IWorldIDBilling.BillingContext memory january = _scope(JAN_2027);
        entries[0] = _entry(january, NULLIFIER + 1);
        entries[0].expiresAtMin = uint64(vm.getBlockTimestamp());
        assertTrue(billing.registerMany(january, entries)[0]);
        (, uint256 decemberCount) = billing.periods(RP_ID, DEC_2026);
        (, uint256 januaryCount) = billing.periods(RP_ID, JAN_2027);
        assertEq(decemberCount, 1);
        assertEq(januaryCount, 1);

        vm.warp(JAN_2027);
        vm.expectRevert(IWorldIDBilling.PeriodNotCurrent.selector);
        billing.registerMany(december, entries);
    }

    function test_Register_OverlapAcrossLeapMonthBoundary() public {
        uint64 february = 1706745600 + 12 hours;
        uint64 march = 1709251200 + 12 hours;
        vm.warp(february);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        _buy(february, 1);
        _buy(march, 1);
        vm.warp(march - 26 hours);

        IWorldIDBilling.BillingContext memory scope = _scope(february);
        assertTrue(
            billing.register(
                scope, _authorize(scope), ISSUER_SCHEMA_ID, uint64(vm.getBlockTimestamp()), NULLIFIER, _proof()
            )
        );
        scope = _scope(march);
        assertTrue(
            billing.register(
                scope, _authorize(scope), ISSUER_SCHEMA_ID, uint64(vm.getBlockTimestamp()), NULLIFIER + 1, _proof()
            )
        );
    }

    ////////////////////////////////////////////////////////////
    //                       PURCHASES                        //
    ////////////////////////////////////////////////////////////

    function test_Quote_ExactAndRoundsUp() public {
        // 10 * $0.05 / $2 = 0.25 WLD
        assertEq(billing.quotePurchase(_scope(NOV_2026), 10), 0.25e18);

        priceSource.set(3e18, NOW);
        // 1 * $0.05 / $3 = 0.0166.. WLD, rounded up
        assertEq(billing.quotePurchase(_scope(NOV_2026), 1), 16666666666666667);
    }

    function test_RejectsNon18DecimalToken() public {
        BillingToken usdcLike = new BillingToken(6);
        vm.expectRevert(IWorldIDBilling.InvalidTokenDecimals.selector);
        billing.setFeeToken(address(usdcLike));

        WorldIDBilling implementation = new WorldIDBilling(address(worldIDVerifier), address(rpRegistry));
        bytes memory initData = abi.encodeCall(
            WorldIDBilling.initialize,
            (
                address(priceSource),
                address(usdcLike),
                feeRecipient,
                PRICE_PER_WORLD_ID,
                MAX_PRICE_AGE,
                MAX_REQUEST_AGE,
                REQUEST_LIFETIME
            )
        );
        vm.expectRevert(IWorldIDBilling.InvalidTokenDecimals.selector);
        new ERC1967Proxy(address(implementation), initData);
    }

    function test_Quote_ProratesPurchaseAndTopUp() public {
        vm.warp(NOV_2026 + 20 days);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        assertEq(billing.quotePurchase(_scope(NOV_2026), 10), 83333333333333334);
        _buy(NOV_2026, 10);
        assertEq(wld.balanceOf(feeRecipient), 83333333333333334);

        vm.warp(NOV_2026 + 21 days);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        _buy(NOV_2026, 5);
        assertEq(wld.balanceOf(feeRecipient), 83333333333333334 + 0.0375e18);
        (uint256 capacity, uint256 count) = billing.periods(RP_ID, NOV_2026);
        assertEq(capacity, 15);
        assertEq(count, 0);
    }

    function test_Quote_OverlapDoesNotChangeProration() public {
        vm.warp(NOV_2026 - 26 hours);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        assertEq(billing.quotePurchase(_scope(NOV_2026), 10), 0.25e18);
        assertEq(billing.quotePurchase(_scope(OCT_2026), 10), 8736559139784947);

        vm.warp(NOV_2026 - 1);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        assertEq(billing.quotePurchase(_scope(OCT_2026), 10), 93339307049);

        vm.warp(NOV_2026);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        assertEq(billing.quotePurchase(_scope(NOV_2026), 10), 0.25e18);
        vm.expectRevert(IWorldIDBilling.PeriodOutsidePurchaseWindow.selector);
        billing.quotePurchase(_scope(OCT_2026), 10);
    }

    function test_Quote_RoundsUpOnce() public {
        billing.setPricePerWorldID(21);
        vm.warp(NOV_2026 + 18 days);
        priceSource.set(10e18, vm.getBlockTimestamp());
        assertEq(billing.quotePurchase(_scope(NOV_2026), 1), 1);

        billing.setPricePerWorldID(5);
        vm.warp(NOV_2026 + 10 days);
        priceSource.set(3e18, vm.getBlockTimestamp());
        assertEq(billing.quotePurchase(_scope(NOV_2026), 1), 2);
    }

    function test_Quote_FullPrecisionProration() public {
        billing.setPricePerWorldID(1e18);
        vm.warp(OCT_2026 + 31 days / 2);
        priceSource.set(USD_PER_WLD, vm.getBlockTimestamp());
        uint256 capacity = 1 << 180;
        assertEq(billing.quotePurchase(_scope(OCT_2026), capacity), capacity * 1e18 / 4);
    }

    function testFuzz_Quote_ProratesCalendarMonths(
        uint8 monthIndex,
        uint256 elapsed,
        uint256 capacity,
        uint256 usdPrice,
        uint256 wldPrice
    ) public {
        uint64[4] memory starts = [uint64(1675209600 + 12 hours), 1706745600 + 12 hours, NOV_2026, OCT_2026];
        uint256[4] memory durations = [uint256(28 days), 29 days, 30 days, 31 days];
        uint256 index = monthIndex % starts.length;
        uint64 start = starts[index];
        uint256 duration = durations[index];
        elapsed = bound(elapsed, 0, duration - 1);
        capacity = bound(capacity, 1, 1e12);
        usdPrice = bound(usdPrice, 1, 1e18);
        wldPrice = bound(wldPrice, 1, 1e20);
        vm.warp(start + elapsed);
        priceSource.set(wldPrice, vm.getBlockTimestamp());
        billing.setPricePerWorldID(usdPrice);

        uint256 numerator = capacity * usdPrice * (duration - elapsed) * 1e18;
        uint256 denominator = duration * wldPrice;
        assertEq(billing.quotePurchase(_scope(start), capacity), (numerator + denominator - 1) / denominator);
    }

    function test_Purchase_TransfersAndAddsCapacity() public {
        vm.expectEmit(address(billing));
        emit IWorldIDBilling.CapacityPurchased(RP_ID, OCT_2026, rp, 10, 205645161290322581);
        vm.prank(rp);
        billing.purchaseCapacity(_scope(OCT_2026), 10, 205645161290322581);

        assertEq(wld.balanceOf(feeRecipient), 205645161290322581);
        (uint256 capacity, uint256 count) = billing.periods(RP_ID, OCT_2026);
        assertEq(capacity, 10);
        assertEq(count, 0);

        _buy(OCT_2026, 5);
        (capacity,) = billing.periods(RP_ID, OCT_2026);
        assertEq(capacity, 15);
        (capacity,) = billing.periods(RP_ID + 1, OCT_2026);
        assertEq(capacity, 0, "no cross-RP capacity");
    }

    function test_Purchase_Window() public {
        _buy(NOV_2026, 1);

        vm.prank(rp);
        vm.expectRevert(IWorldIDBilling.PeriodOutsidePurchaseWindow.selector);
        billing.purchaseCapacity(_scope(DEC_2026), 1, type(uint256).max);

        vm.prank(rp);
        vm.expectRevert(IWorldIDBilling.PeriodOutsidePurchaseWindow.selector);
        billing.purchaseCapacity(_scope(1788220800 + 12 hours), 1, type(uint256).max); // 2026-09-01
    }

    function test_Purchase_RejectsInvalidContext() public {
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);

        scope.periodStart = OCT_2026 + 1;
        vm.expectRevert(IWorldIDBilling.NonCanonicalPeriodStart.selector);
        billing.quotePurchase(scope, 1);

        scope = _scope(OCT_2026);
        scope.chainId = block.chainid + 1;
        vm.expectRevert(IWorldIDBilling.InvalidChainId.selector);
        billing.quotePurchase(scope, 1);

        scope = _scope(OCT_2026);
        scope.billingContract = address(0xBEEF);
        vm.expectRevert(IWorldIDBilling.InvalidBillingContract.selector);
        billing.quotePurchase(scope, 1);

        vm.expectRevert(IWorldIDBilling.ZeroCapacityAmount.selector);
        billing.quotePurchase(_scope(OCT_2026), 0);
    }

    function test_Purchase_RejectsUnknownOrInactiveRp() public {
        rpRegistry.set(RP_ID, OPRF_KEY_ID, signer, false);
        vm.prank(rp);
        vm.expectRevert(MockRpRegistry.RpIdInactive.selector);
        billing.purchaseCapacity(_scope(OCT_2026), 1, type(uint256).max);
        assertEq(wld.balanceOf(feeRecipient), 0);
    }

    function test_Purchase_WindowAcrossYearBoundary() public {
        vm.warp(DEC_2026 + 10 days);
        priceSource.set(USD_PER_WLD, uint64(block.timestamp));
        _buy(DEC_2026, 1);
        _buy(JAN_2027, 1);

        vm.prank(rp);
        vm.expectRevert(IWorldIDBilling.PeriodOutsidePurchaseWindow.selector);
        billing.purchaseCapacity(_scope(1801440000 + 12 hours), 1, type(uint256).max); // 2027-02-01
    }

    function test_Purchase_RejectsAboveMax() public {
        vm.prank(rp);
        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDBilling.MaxWldAmountExceeded.selector, 205645161290322581, 205645161290322581 - 1
            )
        );
        billing.purchaseCapacity(_scope(OCT_2026), 10, 205645161290322581 - 1);
    }

    function test_Purchase_RejectsBadPrices() public {
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);

        priceSource.set(0, NOW);
        vm.expectRevert(IWorldIDBilling.InvalidPrice.selector);
        billing.quotePurchase(scope, 1);

        priceSource.set(USD_PER_WLD, NOW + 1);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDBilling.PriceFromFuture.selector, NOW + 1));
        billing.quotePurchase(scope, 1);

        priceSource.set(USD_PER_WLD, NOW - MAX_PRICE_AGE - 1);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDBilling.StalePrice.selector, NOW - MAX_PRICE_AGE - 1));
        billing.quotePurchase(scope, 1);

        priceSource.set(USD_PER_WLD, NOW - MAX_PRICE_AGE);
        billing.quotePurchase(scope, 1);

        priceSource.setAnswer(-1);
        vm.expectRevert(IWorldIDBilling.InvalidPrice.selector);
        billing.quotePurchase(scope, 1);

        priceSource.setBroken(true);
        vm.expectRevert(IWorldIDBilling.PriceUnavailable.selector);
        billing.quotePurchase(scope, 1);
    }

    function test_Quote_NormalizesFeedDecimals() public {
        priceSource.setDecimals(8);
        priceSource.set(2e8, NOW);
        assertEq(billing.quotePurchase(_scope(NOV_2026), 10), 0.25e18);

        priceSource.setDecimals(20);
        priceSource.set(2e20, NOW);
        assertEq(billing.quotePurchase(_scope(NOV_2026), 10), 0.25e18);
    }

    function test_Purchase_BadPriceKeepsExistingCapacity() public {
        _buy(OCT_2026, 3);
        priceSource.setBroken(true);
        vm.prank(rp);
        vm.expectRevert(IWorldIDBilling.PriceUnavailable.selector);
        billing.purchaseCapacity(_scope(OCT_2026), 1, type(uint256).max);
        (uint256 capacity,) = billing.periods(RP_ID, OCT_2026);
        assertEq(capacity, 3);
    }

    function test_Purchase_RejectsFeeOnTransfer() public {
        FeeOnTransferToken token = new FeeOnTransferToken();
        WorldIDBilling feeBilling = _deploy(address(token));
        token.mint(rp, 1e18);
        vm.startPrank(rp);
        token.approve(address(feeBilling), type(uint256).max);
        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDBilling.FeeTransferMismatch.selector, 205645161290322581, 205645161290322581 - 1
            )
        );
        feeBilling.purchaseCapacity(
            IWorldIDBilling.BillingContext(block.chainid, address(feeBilling), RP_ID, OCT_2026), 10, 1e18
        );
        vm.stopPrank();
    }

    function test_Purchase_PriceChangeKeepsEarlierCapacity() public {
        _buy(NOV_2026, 4);
        billing.setPricePerWorldID(1e18);
        _buy(NOV_2026, 1);
        (uint256 capacity,) = billing.periods(RP_ID, NOV_2026);
        assertEq(capacity, 5);
        assertEq(wld.balanceOf(feeRecipient), 0.1e18 + 0.5e18);
    }

    ////////////////////////////////////////////////////////////
    //                     REGISTRATION                       //
    ////////////////////////////////////////////////////////////

    function test_Register_FirstAndDuplicate() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);

        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        vm.expectEmit(address(billing));
        emit IWorldIDBilling.Registered(RP_ID, OCT_2026, NULLIFIER);
        assertTrue(_register(auth, NULLIFIER));
        assertTrue(billing.isRegistered(NULLIFIER));
        assertTrue(billing.usedNonces(RP_ID, auth.nonce));

        // Duplicate succeeds with `false` even when capacity is exhausted and registrations are paused.
        billing.setPaused(true);
        IWorldIDBilling.RegistrationAuthorization memory auth2 = _authorize(scope);
        assertFalse(_register(auth2, NULLIFIER));
        assertTrue(billing.usedNonces(RP_ID, auth2.nonce));
        (uint256 capacity, uint256 count) = billing.periods(RP_ID, OCT_2026);
        assertEq(capacity, 1);
        assertEq(count, 1);
    }

    function test_Register_PublicInputs() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);

        uint256[15] memory signals;
        signals[0] = NULLIFIER;
        signals[1] = ISSUER_SCHEMA_ID;
        signals[2] = 11;
        signals[3] = 12;
        signals[4] = NOW;
        signals[6] = ROOT;
        signals[7] = 30;
        signals[8] = RP_ID;
        signals[9] = billing.getBillingAction(scope);
        signals[10] = 21;
        signals[11] = 22;
        signals[13] = auth.nonce;
        uint256[4] memory compressed = [uint256(1), 2, 3, 4];
        vm.expectCall(
            address(groth16), abi.encodeCall(MockGroth16Verifier.verifyCompressedProof, (compressed, signals))
        );
        _register(auth, NULLIFIER);
    }

    function _entry(IWorldIDBilling.BillingContext memory scope, uint256 nullifier)
        internal
        returns (IWorldIDBilling.Registration memory)
    {
        return IWorldIDBilling.Registration(_authorize(scope), ISSUER_SCHEMA_ID, NOW, nullifier, _proof());
    }

    function test_RegisterMany_NewAndDuplicate() public {
        _buy(OCT_2026, 2);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        IWorldIDBilling.Registration[] memory entries = new IWorldIDBilling.Registration[](3);
        entries[0] = _entry(scope, NULLIFIER);
        entries[1] = _entry(scope, NULLIFIER + 1);
        entries[2] = _entry(scope, NULLIFIER);

        vm.expectEmit(address(billing));
        emit IWorldIDBilling.Registered(RP_ID, OCT_2026, NULLIFIER);
        vm.expectEmit(address(billing));
        emit IWorldIDBilling.Registered(RP_ID, OCT_2026, NULLIFIER + 1);
        vm.prank(user);
        bool[] memory successes = billing.registerMany(scope, entries);

        assertEq(successes.length, 3);
        assertTrue(successes[0]);
        assertTrue(successes[1]);
        assertFalse(successes[2]);
        (, uint256 count) = billing.periods(RP_ID, OCT_2026);
        assertEq(count, 2);
        for (uint256 i = 0; i < 3; ++i) {
            assertTrue(billing.usedNonces(RP_ID, entries[i].authorization.nonce));
        }
    }

    function test_RegisterMany_RevertsAtomically() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        IWorldIDBilling.Registration[] memory entries = new IWorldIDBilling.Registration[](2);
        entries[0] = _entry(scope, NULLIFIER);
        entries[1] = _entry(scope, NULLIFIER + 1);

        vm.prank(user);
        vm.expectRevert(IWorldIDBilling.CapacityExhausted.selector);
        billing.registerMany(scope, entries);

        assertFalse(billing.isRegistered(NULLIFIER));
        assertFalse(billing.usedNonces(RP_ID, entries[0].authorization.nonce));
        (, uint256 count) = billing.periods(RP_ID, OCT_2026);
        assertEq(count, 0);
    }

    function test_RegisterMany_RejectsReusedNonceInBatch() public {
        _buy(OCT_2026, 2);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        IWorldIDBilling.Registration[] memory entries = new IWorldIDBilling.Registration[](2);
        entries[0] = _entry(scope, NULLIFIER);
        entries[1] = entries[0];
        entries[1].billingNullifier = NULLIFIER + 1;

        vm.prank(user);
        vm.expectRevert(IWorldIDBilling.NonceAlreadyUsed.selector);
        billing.registerMany(scope, entries);
    }

    function test_RegisterMany_Empty() public {
        vm.prank(user);
        bool[] memory successes = billing.registerMany(_scope(OCT_2026), new IWorldIDBilling.Registration[](0));
        assertEq(successes.length, 0);
    }

    function test_Register_VerifiesThroughWorldIDVerifier() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        vm.expectCall(
            address(worldIDVerifier),
            abi.encodeCall(
                IWorldIDVerifier.verifyProofAndSignals,
                (
                    NULLIFIER,
                    billing.getBillingAction(scope),
                    RP_ID,
                    auth.nonce,
                    0,
                    NOW,
                    ISSUER_SCHEMA_ID,
                    0,
                    0,
                    _proof()
                )
            )
        );
        _register(auth, NULLIFIER);
    }

    function test_Register_UsedNonceRevertsEvenForRegisteredNullifier() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(_scope(OCT_2026));
        _register(auth, NULLIFIER);

        vm.expectRevert(IWorldIDBilling.NonceAlreadyUsed.selector);
        _register(auth, NULLIFIER);
    }

    function test_Register_CapacityExhausted() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        _register(_authorize(scope), NULLIFIER);

        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        vm.expectRevert(IWorldIDBilling.CapacityExhausted.selector);
        _register(auth, NULLIFIER + 1);
        assertFalse(billing.usedNonces(RP_ID, auth.nonce), "nonce rolled back");
    }

    function test_Register_NoCapacityWithoutPurchase() public {
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(_scope(OCT_2026));
        vm.expectRevert(IWorldIDBilling.CapacityExhausted.selector);
        _register(auth, NULLIFIER);
    }

    function test_Register_PausedRejectsNew() public {
        _buy(OCT_2026, 1);
        billing.setPaused(true);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(_scope(OCT_2026));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        _register(auth, NULLIFIER);
    }

    function test_Register_InvalidProofRevertsAndKeepsNonce() public {
        _buy(OCT_2026, 1);
        groth16.setFail(true);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(_scope(OCT_2026));
        vm.expectRevert(Verifier.ProofInvalid.selector);
        _register(auth, NULLIFIER);
        assertFalse(billing.usedNonces(RP_ID, auth.nonce));
        (, uint256 count) = billing.periods(RP_ID, OCT_2026);
        assertEq(count, 0);
    }

    function test_Register_InvalidProofRevertsForRegisteredNullifier() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        _register(_authorize(scope), NULLIFIER);

        groth16.setFail(true);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        vm.expectRevert(Verifier.ProofInvalid.selector);
        _register(auth, NULLIFIER);
    }

    function test_Register_OnlyCurrentPeriod() public {
        _buy(NOV_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(NOV_2026);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        vm.prank(user);
        vm.expectRevert(IWorldIDBilling.PeriodNotCurrent.selector);
        billing.register(scope, auth, ISSUER_SCHEMA_ID, NOW, NULLIFIER, _proof());
    }

    function test_Register_RejectsBadAuthorizationFields() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);
        uint256 action = billing.getBillingAction(scope);

        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        auth.version = 2;
        vm.expectRevert(abi.encodeWithSelector(IWorldIDBilling.InvalidAuthorizationVersion.selector, 2));
        _register(auth, NULLIFIER);

        auth = _authorize(scope);
        auth.oprfKeyId = OPRF_KEY_ID + 1;
        vm.expectRevert(IWorldIDBilling.OprfKeyMismatch.selector);
        _register(auth, NULLIFIER);

        auth = _authorize(scope);
        auth.createdAt = NOW + 1;
        auth.expiresAt = NOW + 60;
        auth.signature = _sign(auth, action);
        vm.expectRevert(IWorldIDBilling.RequestNotYetValid.selector);
        _register(auth, NULLIFIER);

        auth = _authorize(scope);
        auth.createdAt = NOW - 60;
        auth.expiresAt = NOW;
        auth.signature = _sign(auth, action);
        vm.expectRevert(IWorldIDBilling.RequestExpired.selector);
        _register(auth, NULLIFIER);

        billing.setRequestLimits(60, REQUEST_LIFETIME);
        auth = _authorize(scope);
        auth.createdAt = NOW - 61;
        auth.signature = _sign(auth, action);
        vm.expectRevert(IWorldIDBilling.RequestTooOld.selector);
        _register(auth, NULLIFIER);

        auth = _authorize(scope);
        auth.expiresAt = NOW + REQUEST_LIFETIME + 1;
        auth.signature = _sign(auth, action);
        vm.expectRevert(IWorldIDBilling.RequestLifetimeTooLong.selector);
        _register(auth, NULLIFIER);

        auth = _authorize(scope);
        auth.createdAt = NOW - 60;
        auth.expiresAt = auth.createdAt + REQUEST_LIFETIME;
        auth.signature = _sign(auth, action);
        assertTrue(_register(auth, NULLIFIER), "limits are inclusive");
    }

    function test_Register_RejectsOprfKeyIdOtherThanRpId() public {
        _buy(OCT_2026, 1);
        rpRegistry.set(RP_ID, OPRF_KEY_ID + 1, signer, true);
        oprfKeyRegistry.set(OPRF_KEY_ID + 1, 31, 32);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(_scope(OCT_2026));
        auth.oprfKeyId = OPRF_KEY_ID + 1;
        vm.expectRevert(IWorldIDBilling.OprfKeyMismatch.selector);
        _register(auth, NULLIFIER);
    }

    function test_Register_PinsOprfKeyPerPeriod() public {
        _buy(OCT_2026, 2);
        _buy(NOV_2026, 1);
        (uint160 keyId, uint256[2] memory key) = billing.getPinnedOprfKey(RP_ID, OCT_2026);
        assertEq(keyId, 0);
        assertEq(key[0], 0);

        groth16.setFail(true);
        IWorldIDBilling.RegistrationAuthorization memory failed = _authorize(_scope(OCT_2026));
        vm.expectRevert();
        _register(failed, NULLIFIER);
        groth16.setFail(false);
        (keyId,) = billing.getPinnedOprfKey(RP_ID, OCT_2026);
        assertEq(keyId, 0, "failed registration does not pin");

        vm.expectEmit(address(billing));
        emit IWorldIDBilling.OprfKeyPinned(RP_ID, OCT_2026, OPRF_KEY_ID);
        assertTrue(_register(_authorize(_scope(OCT_2026)), NULLIFIER));
        (keyId, key) = billing.getPinnedOprfKey(RP_ID, OCT_2026);
        assertEq(keyId, OPRF_KEY_ID);
        assertEq(key[0], 21);
        assertEq(key[1], 22);

        oprfKeyRegistry.set(OPRF_KEY_ID, 31, 32);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(_scope(OCT_2026));
        vm.expectRevert(IWorldIDBilling.PinnedOprfKeyChanged.selector);
        _register(auth, NULLIFIER + 1);
        vm.expectRevert(IWorldIDBilling.PinnedOprfKeyChanged.selector);
        _register(auth, NULLIFIER);

        vm.warp(NOV_2026 - 26 hours);
        IWorldIDBilling.BillingContext memory november = _scope(NOV_2026);
        assertTrue(
            billing.register(
                november,
                _authorize(november),
                ISSUER_SCHEMA_ID,
                uint64(vm.getBlockTimestamp()),
                NULLIFIER + 2,
                _proof()
            )
        );
        (keyId, key) = billing.getPinnedOprfKey(RP_ID, NOV_2026);
        assertEq(key[0], 31);
        assertEq(key[1], 32);
        (, key) = billing.getPinnedOprfKey(RP_ID, OCT_2026);
        assertEq(key[0], 21, "earlier pin unchanged");
    }

    function test_Register_RejectsBadEoaSignatures() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);

        // Signed over a different action.
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        auth.signature = _sign(auth, 123);
        vm.expectRevert(IWorldIDBilling.InvalidRpSignature.selector);
        _register(auth, NULLIFIER);

        // Malleable high-s form of a valid signature.
        auth = _authorize(scope);
        (bytes32 r, bytes32 s, uint8 v) = _split(auth.signature);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        auth.signature = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(IWorldIDBilling.InvalidRpSignature.selector);
        _register(auth, NULLIFIER);

        auth = _authorize(scope);
        auth.signature = hex"1234";
        vm.expectRevert(IWorldIDBilling.InvalidRpSignature.selector);
        _register(auth, NULLIFIER);

        auth = _authorize(scope);
        auth.wip101Data = hex"01";
        vm.expectRevert(IWIP101.Wip101DataOnEoa.selector);
        _register(auth, NULLIFIER);
    }

    function test_Register_ResolvesCurrentSigner() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(_scope(OCT_2026));
        rpRegistry.set(RP_ID, OPRF_KEY_ID, makeAddr("rotatedSigner"), true);
        vm.expectRevert(IWorldIDBilling.InvalidRpSignature.selector);
        _register(auth, NULLIFIER);

        rpRegistry.set(RP_ID, OPRF_KEY_ID, signer, false);
        vm.expectRevert(MockRpRegistry.RpIdInactive.selector);
        _register(auth, NULLIFIER);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function test_Register_Wip101() public {
        _buy(OCT_2026, 2);
        Wip101Signer contractSigner = new Wip101Signer();
        rpRegistry.set(RP_ID, OPRF_KEY_ID, address(contractSigner), true);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);

        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        auth.signature = "";
        auth.wip101Data = hex"abcdef";
        vm.expectCall(
            address(contractSigner),
            abi.encodeCall(
                IWIP101.verifyRpRequest,
                (1, auth.nonce, auth.createdAt, auth.expiresAt, billing.getBillingAction(scope), auth.wip101Data)
            )
        );
        assertTrue(_register(auth, NULLIFIER));

        auth = _authorize(scope);
        auth.wip101Data = new bytes(1025);
        vm.expectRevert(IWIP101.Wip101DataTooLong.selector);
        _register(auth, NULLIFIER + 1);

        contractSigner.setMode(Wip101Signer.Mode.WrongMagic);
        auth = _authorize(scope);
        vm.expectRevert(IWIP101.Wip101Rejected.selector);
        _register(auth, NULLIFIER + 1);

        contractSigner.setMode(Wip101Signer.Mode.Revert);
        auth = _authorize(scope);
        vm.expectRevert(IWIP101.Wip101Rejected.selector);
        _register(auth, NULLIFIER + 1);

        rpRegistry.set(RP_ID, OPRF_KEY_ID, address(new MalformedWip101Signer()), true);
        auth = _authorize(scope);
        vm.expectRevert(IWIP101.Wip101Rejected.selector);
        _register(auth, NULLIFIER + 1);
        rpRegistry.set(RP_ID, OPRF_KEY_ID, address(contractSigner), true);

        contractSigner.setMode(Wip101Signer.Mode.NoInterface);
        auth = _authorize(scope);
        vm.expectRevert(IWIP101.Wip101Unsupported.selector);
        _register(auth, NULLIFIER + 1);
    }

    function test_Register_CredentialChecks() public {
        _buy(OCT_2026, 1);
        IWorldIDBilling.BillingContext memory scope = _scope(OCT_2026);

        IWorldIDBilling.RegistrationAuthorization memory auth = _authorize(scope);
        uint256[5] memory proof = _proof();
        proof[4] = ROOT + 1;
        vm.prank(user);
        vm.expectRevert(IWorldIDVerifier.InvalidMerkleRoot.selector);
        billing.register(scope, auth, ISSUER_SCHEMA_ID, NOW, NULLIFIER, proof);

        vm.prank(user);
        vm.expectRevert(IWorldIDVerifier.UnregisteredIssuerSchemaId.selector);
        billing.register(scope, auth, ISSUER_SCHEMA_ID + 1, NOW, NULLIFIER, _proof());

        uint64 tooOld = uint64(NOW - EXPIRATION_THRESHOLD - 1);
        vm.prank(user);
        vm.expectRevert(IWorldIDVerifier.ExpirationTooOld.selector);
        billing.register(scope, auth, ISSUER_SCHEMA_ID, tooOld, NULLIFIER, _proof());
    }

    ////////////////////////////////////////////////////////////
    //                    ADMINISTRATION                      //
    ////////////////////////////////////////////////////////////

    function test_Admin_OnlyOwner() public {
        address stranger = makeAddr("stranger");
        bytes memory err = abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger);
        vm.startPrank(stranger);
        vm.expectRevert(err);
        billing.setPricePerWorldID(1);
        vm.expectRevert(err);
        billing.setMaxPriceAge(1);
        vm.expectRevert(err);
        billing.setPaused(true);
        vm.expectRevert(err);
        billing.setFeeToken(address(wld));
        vm.expectRevert(err);
        billing.setFeeRecipient(stranger);
        vm.expectRevert(err);
        billing.setPriceSource(stranger);
        vm.expectRevert(err);
        billing.setRequestLimits(1, 1);
        vm.stopPrank();
    }

    function test_Admin_RejectsUnsafeValues() public {
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        billing.setFeeToken(address(0));
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        billing.setFeeRecipient(address(0));
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        billing.setPriceSource(address(0));
        vm.expectRevert(IWorldIDBilling.InvalidPricePerWorldID.selector);
        billing.setPricePerWorldID(0);
        vm.expectRevert(IWorldIDBilling.InvalidMaxPriceAge.selector);
        billing.setMaxPriceAge(0);
        vm.expectRevert(IWorldIDBilling.InvalidRequestLimits.selector);
        billing.setRequestLimits(0, 1);
        vm.expectRevert(IWorldIDBilling.InvalidRequestLimits.selector);
        billing.setRequestLimits(1, 0);

        WorldIDBilling implementation = new WorldIDBilling(address(worldIDVerifier), address(rpRegistry));
        bytes memory initData = abi.encodeCall(
            WorldIDBilling.initialize,
            (address(priceSource), address(wld), feeRecipient, PRICE_PER_WORLD_ID, MAX_PRICE_AGE, 0, REQUEST_LIFETIME)
        );
        vm.expectRevert(IWorldIDBilling.InvalidRequestLimits.selector);
        new ERC1967Proxy(address(implementation), initData);
    }

    function test_Admin_SettersEmitAndApply() public {
        vm.expectEmit(address(billing));
        emit IWorldIDBilling.PricePerWorldIDUpdated(PRICE_PER_WORLD_ID, 1e18);
        billing.setPricePerWorldID(1e18);
        assertEq(billing.pricePerWorldID(), 1e18);

        vm.expectEmit(address(billing));
        emit IWorldIDBilling.RequestLimitsUpdated(MAX_REQUEST_AGE, REQUEST_LIFETIME, 2 minutes, 3 minutes);
        billing.setRequestLimits(2 minutes, 3 minutes);
        assertEq(billing.maxRequestAge(), 2 minutes);
        assertEq(billing.maxRequestLifetime(), 3 minutes);

        vm.expectEmit(address(billing));
        emit PausableUpgradeable.Paused(address(this));
        billing.setPaused(true);
        assertTrue(billing.paused());

        vm.expectEmit(address(billing));
        emit PausableUpgradeable.Unpaused(address(this));
        billing.setPaused(false);
        assertFalse(billing.paused());

        vm.expectEmit(address(billing));
        emit WorldIDBase.FeeRecipientUpdated(feeRecipient, user);
        billing.setFeeRecipient(user);
        assertEq(billing.getFeeRecipient(), user);
        assertEq(billing.owner(), address(this));
    }

    function test_Implementation_CannotBeUsedDirectly() public {
        WorldIDBilling implementation = new WorldIDBilling(address(worldIDVerifier), address(rpRegistry));
        vm.expectRevert();
        implementation.quotePurchase(_scope(OCT_2026), 1);
    }

    function test_Constructor_SetsImmutables() public {
        assertEq(address(billing.WORLD_ID_VERIFIER()), address(worldIDVerifier));
        assertEq(address(billing.RP_REGISTRY()), address(rpRegistry));

        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        new WorldIDBilling(address(0), address(rpRegistry));
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        new WorldIDBilling(address(worldIDVerifier), address(0));
    }
}
