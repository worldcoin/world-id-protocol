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
    uint64 constant OCT_2026 = 1790812800;
    uint64 constant NOV_2026 = 1793491200;
    uint64 constant DEC_2026 = 1796083200;
    uint64 constant JAN_2027 = 1798761600;
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
            WorldIDBilling.initialize, (address(priceSource), token, feeRecipient, PRICE_PER_WORLD_ID, MAX_PRICE_AGE)
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
        _assertPeriod(1709164800, 1706745600, 1709251200); // 2024-02-29 (leap day)
        _assertPeriod(1832976000 + 28 days, 1832976000, 1835481600); // 2028-02-29
        _assertPeriod(0, 0, 2678400);
    }

    function _assertPeriod(uint64 timestamp, uint64 start, uint64 end) internal view {
        (uint64 periodStart, uint64 periodEnd) = billing.getBillingPeriod(timestamp);
        assertEq(periodStart, start, "start");
        assertEq(periodEnd, end, "end");
    }

    function testFuzz_GetBillingPeriod_ContainsTimestamp(uint64 timestamp) public view {
        timestamp = uint64(bound(timestamp, 0, 253402300799)); // through 9999-12-31
        (uint64 periodStart, uint64 periodEnd) = billing.getBillingPeriod(timestamp);
        assertLe(periodStart, timestamp);
        assertGt(periodEnd, timestamp);
        assertGe(periodEnd - periodStart, 28 days);
        assertLe(periodEnd - periodStart, 31 days);
        assertEq(periodStart % 1 days, 0);
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

    ////////////////////////////////////////////////////////////
    //                       PURCHASES                        //
    ////////////////////////////////////////////////////////////

    function test_Quote_ExactAndRoundsUp() public {
        // 10 * $0.05 / $2 = 0.25 WLD
        assertEq(billing.quotePurchase(_scope(OCT_2026), 10), 0.25e18);

        priceSource.set(3e18, NOW);
        // 1 * $0.05 / $3 = 0.0166.. WLD, rounded up
        assertEq(billing.quotePurchase(_scope(OCT_2026), 1), 16666666666666667);
    }

    function test_RejectsNon18DecimalToken() public {
        BillingToken usdcLike = new BillingToken(6);
        vm.expectRevert(IWorldIDBilling.InvalidTokenDecimals.selector);
        billing.setFeeToken(address(usdcLike));

        WorldIDBilling implementation = new WorldIDBilling(address(worldIDVerifier), address(rpRegistry));
        bytes memory initData = abi.encodeCall(
            WorldIDBilling.initialize,
            (address(priceSource), address(usdcLike), feeRecipient, PRICE_PER_WORLD_ID, MAX_PRICE_AGE)
        );
        vm.expectRevert(IWorldIDBilling.InvalidTokenDecimals.selector);
        new ERC1967Proxy(address(implementation), initData);
    }

    function test_Purchase_TransfersAndAddsCapacity() public {
        vm.expectEmit(address(billing));
        emit IWorldIDBilling.CapacityPurchased(RP_ID, OCT_2026, rp, 10, 0.25e18);
        vm.prank(rp);
        billing.purchaseCapacity(_scope(OCT_2026), 10, 0.25e18);

        assertEq(wld.balanceOf(feeRecipient), 0.25e18);
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
        _buy(DEC_2026, 1);

        vm.prank(rp);
        vm.expectRevert(IWorldIDBilling.PeriodOutsidePurchaseWindow.selector);
        billing.purchaseCapacity(_scope(JAN_2027), 1, type(uint256).max);

        vm.prank(rp);
        vm.expectRevert(IWorldIDBilling.PeriodOutsidePurchaseWindow.selector);
        billing.purchaseCapacity(_scope(1788220800), 1, type(uint256).max); // 2026-09-01
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
        _buy(1801440000, 1); // 2027-02-01

        vm.prank(rp);
        vm.expectRevert(IWorldIDBilling.PeriodOutsidePurchaseWindow.selector);
        billing.purchaseCapacity(_scope(1803859200), 1, type(uint256).max); // 2027-03-01
    }

    function test_Purchase_RejectsAboveMax() public {
        vm.prank(rp);
        vm.expectRevert(abi.encodeWithSelector(IWorldIDBilling.MaxWldAmountExceeded.selector, 0.25e18, 0.25e18 - 1));
        billing.purchaseCapacity(_scope(OCT_2026), 10, 0.25e18 - 1);
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
        assertEq(billing.quotePurchase(_scope(OCT_2026), 10), 0.25e18);

        priceSource.setDecimals(20);
        priceSource.set(2e20, NOW);
        assertEq(billing.quotePurchase(_scope(OCT_2026), 10), 0.25e18);
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
        vm.expectRevert(abi.encodeWithSelector(IWorldIDBilling.FeeTransferMismatch.selector, 0.25e18, 0.25e18 - 1));
        feeBilling.purchaseCapacity(
            IWorldIDBilling.BillingContext(block.chainid, address(feeBilling), RP_ID, OCT_2026), 10, 1e18
        );
        vm.stopPrank();
    }

    function test_Purchase_PriceChangeKeepsEarlierCapacity() public {
        _buy(OCT_2026, 4);
        billing.setPricePerWorldID(1e18);
        _buy(OCT_2026, 1);
        (uint256 capacity,) = billing.periods(RP_ID, OCT_2026);
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
        assertTrue(billing.isRegistered(RP_ID, OCT_2026, NULLIFIER));
        assertTrue(billing.usedNonces(RP_ID, OCT_2026, auth.nonce));

        // Duplicate succeeds with `false` even when capacity is exhausted and registrations are paused.
        billing.setPaused(true);
        IWorldIDBilling.RegistrationAuthorization memory auth2 = _authorize(scope);
        assertFalse(_register(auth2, NULLIFIER));
        assertTrue(billing.usedNonces(RP_ID, OCT_2026, auth2.nonce));
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
            assertTrue(billing.usedNonces(RP_ID, OCT_2026, entries[i].authorization.nonce));
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

        assertFalse(billing.isRegistered(RP_ID, OCT_2026, NULLIFIER));
        assertFalse(billing.usedNonces(RP_ID, OCT_2026, entries[0].authorization.nonce));
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
        assertFalse(billing.usedNonces(RP_ID, OCT_2026, auth.nonce), "nonce rolled back");
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
        assertFalse(billing.usedNonces(RP_ID, OCT_2026, auth.nonce));
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
        vm.expectRevert(IWorldIDBilling.Wip101DataOnEoa.selector);
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
        vm.expectRevert(IWorldIDBilling.Wip101DataTooLong.selector);
        _register(auth, NULLIFIER + 1);

        contractSigner.setMode(Wip101Signer.Mode.WrongMagic);
        auth = _authorize(scope);
        vm.expectRevert(IWorldIDBilling.Wip101Rejected.selector);
        _register(auth, NULLIFIER + 1);

        contractSigner.setMode(Wip101Signer.Mode.Revert);
        auth = _authorize(scope);
        vm.expectRevert(IWorldIDBilling.Wip101Rejected.selector);
        _register(auth, NULLIFIER + 1);

        rpRegistry.set(RP_ID, OPRF_KEY_ID, address(new MalformedWip101Signer()), true);
        auth = _authorize(scope);
        vm.expectRevert(IWorldIDBilling.Wip101Rejected.selector);
        _register(auth, NULLIFIER + 1);
        rpRegistry.set(RP_ID, OPRF_KEY_ID, address(contractSigner), true);

        contractSigner.setMode(Wip101Signer.Mode.NoInterface);
        auth = _authorize(scope);
        vm.expectRevert(IWorldIDBilling.Wip101Unsupported.selector);
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
    }

    function test_Admin_SettersEmitAndApply() public {
        vm.expectEmit(address(billing));
        emit IWorldIDBilling.PricePerWorldIDUpdated(PRICE_PER_WORLD_ID, 1e18);
        billing.setPricePerWorldID(1e18);
        assertEq(billing.pricePerWorldID(), 1e18);

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
