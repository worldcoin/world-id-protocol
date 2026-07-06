// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {BillingContract} from "../../src/core/BillingContract.sol";
import {IBillingContract} from "../../src/core/interfaces/IBillingContract.sol";
import {WorldIDBase} from "../../src/core/abstract/WorldIDBase.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

/// @dev Minimal stand-in for the OprfKeyRegistry node set the BillingContract authenticates against.
contract OprfKeyRegistryMock {
    address[] public peers;

    function setPeers(address[] memory p) external {
        peers = p;
    }

    function numPeers() external view returns (uint16) {
        return uint16(peers.length);
    }

    function peerAddresses(uint256 index) external view returns (address) {
        return peers[index];
    }
}

contract BillingContractTest is Test {
    // EIP-712 typehashes (mirror the contract constants).
    bytes32 internal constant BILLING_VOTE_CHUNK_TYPEHASH = keccak256(
        "BillingVoteChunk(uint32 epoch,uint32 chunkIndex,bool isFinal,RpCount[] counts)RpCount(uint64 rpId,uint64 count)"
    );
    bytes32 internal constant RPCOUNT_TYPEHASH = keccak256("RpCount(uint64 rpId,uint64 count)");

    // Timing config.
    uint64 internal constant GENESIS = 1_000_000;
    uint64 internal constant EPOCH_LEN = 100;
    uint64 internal constant VOTING = 100;
    uint64 internal constant PAYMENT = 200;
    uint32 internal constant REBATE = 10;

    BillingContract internal billing;
    ERC20Mock internal feeToken;
    OprfKeyRegistryMock internal oprf;

    address internal owner;
    address internal feeRecipient;
    address internal payer;

    // OPRF node keypairs.
    uint256 internal pk1 = 0xA11CE;
    uint256 internal pk2 = 0xB0B;
    uint256 internal pk3 = 0xC0FFEE;
    uint256 internal pk4 = 0xD00D;
    uint256 internal pk5 = 0xE1F;
    address internal node1;
    address internal node2;
    address internal node3;
    address internal node4;
    address internal node5;
    // A key that is not part of the node set.
    uint256 internal pkOutsider = 0xBAD;

    function setUp() public {
        owner = address(this);
        feeRecipient = vm.addr(0x9999);
        payer = vm.addr(0x7777);

        node1 = vm.addr(pk1);
        node2 = vm.addr(pk2);
        node3 = vm.addr(pk3);
        node4 = vm.addr(pk4);
        node5 = vm.addr(pk5);

        feeToken = new ERC20Mock();
        oprf = new OprfKeyRegistryMock();
        _setPeers3();

        billing = _deploy(GENESIS, EPOCH_LEN, VOTING, PAYMENT, _tiers(100, 10, 5), REBATE);

        vm.warp(GENESIS); // start at epoch 0's genesis
    }

    ////////////////////////////////////////////////////////////
    //                        Helpers                         //
    ////////////////////////////////////////////////////////////

    function _deploy(
        uint64 genesis,
        uint64 epochLength,
        uint64 votingWindow,
        uint64 paymentWindow,
        IBillingContract.Tier[] memory tiers,
        uint32 rebate
    ) internal returns (BillingContract) {
        BillingContract impl = new BillingContract();
        bytes memory initData =
            _initData(feeRecipient, genesis, epochLength, votingWindow, paymentWindow, tiers, rebate);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        return BillingContract(address(proxy));
    }

    function _initData(
        address recipient,
        uint64 genesis,
        uint64 epochLength,
        uint64 votingWindow,
        uint64 paymentWindow,
        IBillingContract.Tier[] memory tiers,
        uint32 rebate
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            BillingContract.initialize.selector,
            recipient,
            address(feeToken),
            address(oprf),
            genesis,
            epochLength,
            votingWindow,
            paymentWindow,
            tiers,
            rebate
        );
    }

    function _tiers(uint256 upTo0, uint256 rate0, uint256 rate1)
        internal
        pure
        returns (IBillingContract.Tier[] memory t)
    {
        t = new IBillingContract.Tier[](2);
        t[0] = IBillingContract.Tier({upTo: upTo0, rate: rate0});
        t[1] = IBillingContract.Tier({upTo: type(uint256).max, rate: rate1});
    }

    function _setPeers3() internal {
        address[] memory p = new address[](3);
        p[0] = node1;
        p[1] = node2;
        p[2] = node3;
        oprf.setPeers(p);
    }

    function _counts(uint64[] memory rpIds, uint64[] memory cs)
        internal
        pure
        returns (IBillingContract.RpCount[] memory c)
    {
        c = new IBillingContract.RpCount[](rpIds.length);
        for (uint256 i = 0; i < rpIds.length; i++) {
            c[i] = IBillingContract.RpCount({rpId: rpIds[i], count: cs[i]});
        }
    }

    function _one(uint64 rpId, uint64 count) internal pure returns (IBillingContract.RpCount[] memory c) {
        c = new IBillingContract.RpCount[](1);
        c[0] = IBillingContract.RpCount({rpId: rpId, count: count});
    }

    function _sign(uint256 pk, uint32 epoch, IBillingContract.RpCount[] memory counts)
        internal
        view
        returns (IBillingContract.SignedVoteChunk memory)
    {
        return _signChunk(pk, epoch, 0, true, counts);
    }

    function _signChunk(
        uint256 pk,
        uint32 epoch,
        uint32 chunkIndex,
        bool isFinal,
        IBillingContract.RpCount[] memory counts
    ) internal view returns (IBillingContract.SignedVoteChunk memory) {
        bytes32[] memory hashes = new bytes32[](counts.length);
        for (uint256 i = 0; i < counts.length; i++) {
            hashes[i] = keccak256(abi.encode(RPCOUNT_TYPEHASH, counts[i].rpId, counts[i].count));
        }
        bytes32 countsHash = keccak256(abi.encodePacked(hashes));
        bytes32 structHash = keccak256(abi.encode(BILLING_VOTE_CHUNK_TYPEHASH, epoch, chunkIndex, isFinal, countsHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", billing.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return IBillingContract.SignedVoteChunk({
            chunkIndex: chunkIndex, isFinal: isFinal, counts: counts, signature: abi.encodePacked(r, s, v)
        });
    }

    /// @dev Warp to the start of `epoch`'s voting window.
    function _openVoting(uint32 epoch) internal {
        vm.warp(billing.epochEnd(epoch));
    }

    /// @dev Warp to just after `epoch`'s voting window closes.
    function _closeVoting(uint32 epoch) internal {
        vm.warp(billing.epochEnd(epoch) + VOTING);
    }

    /// @dev Submit a single-rp vote from each provided key for `epoch` (opens the window first).
    function _voteSingle(uint32 epoch, uint64 rpId, uint64 count, uint256[] memory pks) internal {
        _openVoting(epoch);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            votes[i] = _sign(pks[i], epoch, _one(rpId, count));
        }
        billing.submitBillingVotes(epoch, votes);
    }

    function _pks2() internal view returns (uint256[] memory pks) {
        pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk2;
    }

    function _pks3() internal view returns (uint256[] memory pks) {
        pks = new uint256[](3);
        pks[0] = pk1;
        pks[1] = pk2;
        pks[2] = pk3;
    }

    ////////////////////////////////////////////////////////////
    //                      Initialization                    //
    ////////////////////////////////////////////////////////////

    function test_Initialize_setsState() public view {
        assertEq(billing.getOprfKeyRegistry(), address(oprf));
        assertEq(billing.getFeeRecipient(), feeRecipient);
        assertEq(billing.getFeeToken(), address(feeToken));
        assertEq(billing.getRebatePeriodEpochs(), REBATE);
        assertEq(billing.getTierSchedule().length, 2);
        assertEq(billing.epochEnd(0), GENESIS + EPOCH_LEN);
    }

    function test_Initialize_revertsZeroAddress() public {
        BillingContract impl = new BillingContract();
        bytes memory d = _initData(address(0), GENESIS, EPOCH_LEN, VOTING, PAYMENT, _tiers(100, 10, 5), REBATE);
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), d);
    }

    function test_Initialize_revertsVotingWindowGtEpoch() public {
        BillingContract impl = new BillingContract();
        bytes memory d = _initData(feeRecipient, GENESIS, EPOCH_LEN, EPOCH_LEN + 1, PAYMENT, _tiers(100, 10, 5), REBATE);
        vm.expectRevert(IBillingContract.InvalidTiming.selector);
        new ERC1967Proxy(address(impl), d);
    }

    function test_Initialize_revertsZeroTiming() public {
        BillingContract impl = new BillingContract();
        bytes memory d = _initData(feeRecipient, GENESIS, 0, VOTING, PAYMENT, _tiers(100, 10, 5), REBATE);
        vm.expectRevert(IBillingContract.InvalidTiming.selector);
        new ERC1967Proxy(address(impl), d);
    }

    function test_Initialize_revertsZeroRebate() public {
        BillingContract impl = new BillingContract();
        bytes memory d = _initData(feeRecipient, GENESIS, EPOCH_LEN, VOTING, PAYMENT, _tiers(100, 10, 5), 0);
        vm.expectRevert(IBillingContract.InvalidTiming.selector);
        new ERC1967Proxy(address(impl), d);
    }

    ////////////////////////////////////////////////////////////
    //                     Vote submission                    //
    ////////////////////////////////////////////////////////////

    function test_SubmitVotes_happy() public {
        vm.expectEmit(true, false, false, true, address(billing));
        emit IBillingContract.VoteChunksSubmitted(0, 2);
        _voteSingle(0, 1, 50, _pks2());

        // Median visible while the epoch is retained (not yet finalized).
        assertEq(billing.epochRequestCount(0, 1), 50);
    }

    function test_SubmitVotes_chunkedVoteCompletesAcrossChunks() public {
        _openVoting(0);

        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 2;
        uint64[] memory counts = new uint64[](2);
        counts[0] = 50;
        counts[1] = 90;

        IBillingContract.SignedVoteChunk[] memory chunks = new IBillingContract.SignedVoteChunk[](3);
        chunks[0] = _signChunk(pk1, 0, 0, false, _one(1, 50));
        chunks[1] = _signChunk(pk1, 0, 1, true, _one(2, 90));
        chunks[2] = _sign(pk2, 0, _counts(rpIds, counts));
        billing.submitBillingVotes(0, chunks);

        assertEq(billing.epochRequestCount(0, 1), 50);
        assertEq(billing.epochRequestCount(0, 2), 90);
    }

    function test_SubmitVotes_incompleteChunkedVoteDoesNotCountTowardQuorum() public {
        _openVoting(0);

        IBillingContract.SignedVoteChunk[] memory chunks = new IBillingContract.SignedVoteChunk[](2);
        chunks[0] = _signChunk(pk1, 0, 0, false, _one(1, 100));
        chunks[1] = _sign(pk2, 0, _one(1, 10));
        billing.submitBillingVotes(0, chunks);

        assertEq(billing.epochRequestCount(0, 1), 0, "only one completed voter");
        _closeVoting(0);
        billing.finalizeEpochs(0, 100);
        assertEq(billing.outstandingDebt(1), 0);
    }

    function test_SubmitVotes_revertsUnexpectedChunkIndex() public {
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory chunks = new IBillingContract.SignedVoteChunk[](1);
        chunks[0] = _signChunk(pk1, 0, 1, true, _one(1, 10));
        vm.expectRevert(IBillingContract.UnexpectedChunkIndex.selector);
        billing.submitBillingVotes(0, chunks);
    }

    function test_SubmitVotes_revertsCrossChunkCountsNotAscending() public {
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory first = new IBillingContract.SignedVoteChunk[](1);
        first[0] = _signChunk(pk1, 0, 0, false, _one(2, 20));
        billing.submitBillingVotes(0, first);

        IBillingContract.SignedVoteChunk[] memory second = new IBillingContract.SignedVoteChunk[](1);
        second[0] = _signChunk(pk1, 0, 1, true, _one(1, 10));
        vm.expectRevert(IBillingContract.CountsNotAscending.selector);
        billing.submitBillingVotes(0, second);
    }

    function test_SubmitVotes_revertsBeforeWindow() public {
        // Before epoch 0's voting window opens (still inside the epoch).
        vm.warp(billing.epochEnd(0) - 1);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](1);
        votes[0] = _sign(pk1, 0, _one(1, 10));
        vm.expectRevert(IBillingContract.VotingWindowNotOpen.selector);
        billing.submitBillingVotes(0, votes);
    }

    function test_SubmitVotes_revertsAfterWindow() public {
        _closeVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](1);
        votes[0] = _sign(pk1, 0, _one(1, 10));
        vm.expectRevert(IBillingContract.VotingWindowClosed.selector);
        billing.submitBillingVotes(0, votes);
    }

    function test_SubmitVotes_revertsNotANode() public {
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](1);
        votes[0] = _sign(pkOutsider, 0, _one(1, 10));
        vm.expectRevert(IBillingContract.NotANode.selector);
        billing.submitBillingVotes(0, votes);
    }

    function test_SubmitVotes_revertsVoteAlreadyClosed() public {
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](2);
        votes[0] = _sign(pk1, 0, _one(1, 10));
        votes[1] = _sign(pk1, 0, _one(1, 20));
        vm.expectRevert(IBillingContract.VoteAlreadyClosed.selector);
        billing.submitBillingVotes(0, votes);
    }

    function test_SubmitVotes_revertsCountsNotAscending() public {
        _openVoting(0);
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 2;
        rpIds[1] = 1; // descending
        uint64[] memory cs = new uint64[](2);
        cs[0] = 10;
        cs[1] = 20;
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](1);
        votes[0] = _sign(pk1, 0, _counts(rpIds, cs));
        vm.expectRevert(IBillingContract.CountsNotAscending.selector);
        billing.submitBillingVotes(0, votes);
    }

    function test_SubmitVotes_revertsZeroCount() public {
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](1);
        votes[0] = _sign(pk1, 0, _one(1, 0));
        vm.expectRevert(IBillingContract.ZeroCount.selector);
        billing.submitBillingVotes(0, votes);
    }

    function test_SubmitVotes_revertsNoNodes() public {
        // With no snapshot/NoNodesRegistered guard, an empty node set makes every signer fail the
        // live NotANode check.
        oprf.setPeers(new address[](0));
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](1);
        votes[0] = _sign(pk1, 0, _one(1, 10));
        vm.expectRevert(IBillingContract.NotANode.selector);
        billing.submitBillingVotes(0, votes);
    }

    /// @dev submit must NOT finalize as a side effect (keeper-only finalization).
    function test_SubmitVotes_doesNotFinalize() public {
        _voteSingle(0, 1, 50, _pks2());
        // Open epoch 1 and submit; epoch 0 is now closed but must remain unfinalized.
        _voteSingle(1, 1, 50, _pks2());
        assertEq(billing.outstandingDebt(1), 0, "submit must not finalize epoch 0");
        // Still retained (not pruned).
        assertEq(billing.epochRequestCount(0, 1), 50);
    }

    ////////////////////////////////////////////////////////////
    //                  Finalization + median                 //
    ////////////////////////////////////////////////////////////

    function test_Finalize_happyDebtAndEvent() public {
        _voteSingle(0, 1, 50, _pks2());
        _closeVoting(0);

        vm.expectEmit(true, true, false, true, address(billing));
        emit IBillingContract.EpochRpFinalized(0, 1, 50, 500); // 50 * 10 (tier 0)
        billing.finalizeEpochs(0, 100);

        assertEq(billing.outstandingDebt(1), 500);
        // Pruned after finalize.
        assertEq(billing.epochRequestCount(0, 1), 0);
    }

    function test_Finalize_belowQuorumZero() public {
        // Only 1 of 3 nodes votes → below quorum (2) → median 0, no debt.
        uint256[] memory pks = new uint256[](1);
        pks[0] = pk1;
        _voteSingle(0, 1, 50, pks);
        _closeVoting(0);
        billing.finalizeEpochs(0, 100);
        assertEq(billing.outstandingDebt(1), 0);
    }

    function test_Median_oddV() public {
        // n=3, all 3 vote counts [40, 50, 60] → lower median = 50.
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](3);
        votes[0] = _sign(pk1, 0, _one(1, 40));
        votes[1] = _sign(pk2, 0, _one(1, 60));
        votes[2] = _sign(pk3, 0, _one(1, 50));
        billing.submitBillingVotes(0, votes);
        assertEq(billing.epochRequestCount(0, 1), 50);
    }

    function test_Median_evenV() public {
        // n=4, all 4 vote counts [40,50,60,70] → lower median index (4-1)/2 = 1 → 50.
        address[] memory p = new address[](4);
        p[0] = node1;
        p[1] = node2;
        p[2] = node3;
        p[3] = node4;
        oprf.setPeers(p);

        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](4);
        votes[0] = _sign(pk1, 0, _one(1, 70));
        votes[1] = _sign(pk2, 0, _one(1, 40));
        votes[2] = _sign(pk3, 0, _one(1, 60));
        votes[3] = _sign(pk4, 0, _one(1, 50));
        billing.submitBillingVotes(0, votes);
        assertEq(billing.epochRequestCount(0, 1), 50);
    }

    function test_Median_zeroFill() public {
        // n=3, all 3 vote but only 2 report rp 1 (counts 5, 9); third omits → 0.
        // Full sorted [0,5,9], lower-median idx (3-1)/2=1 → 5.
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](3);
        votes[0] = _sign(pk1, 0, _one(1, 5));
        votes[1] = _sign(pk2, 0, _one(1, 9));
        votes[2] = _sign(pk3, 0, _one(2, 7)); // reports a different rp, so rp 1 gets a zero
        billing.submitBillingVotes(0, votes);
        assertEq(billing.epochRequestCount(0, 1), 5);
    }

    function test_Median_zeroFillBelowMedianReturnsZero() public {
        // n=5, all 5 vote but only 2 report rp 1 → 3 zeros. idx (5-1)/2=2 < zeros(3) → 0.
        address[] memory p = new address[](5);
        p[0] = node1;
        p[1] = node2;
        p[2] = node3;
        p[3] = node4;
        p[4] = node5;
        oprf.setPeers(p);

        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](5);
        votes[0] = _sign(pk1, 0, _one(1, 5));
        votes[1] = _sign(pk2, 0, _one(1, 9));
        votes[2] = _sign(pk3, 0, _one(2, 7));
        votes[3] = _sign(pk4, 0, _one(2, 7));
        votes[4] = _sign(pk5, 0, _one(2, 7));
        billing.submitBillingVotes(0, votes);
        assertEq(billing.epochRequestCount(0, 1), 0);
    }

    function test_Finalize_chunkedResumesMidEpoch() public {
        // 2 voters report rps 1,2,3 each count 10 (quorum met). rpList = [1,2,3].
        _openVoting(0);
        uint64[] memory rpIds = new uint64[](3);
        rpIds[0] = 1;
        rpIds[1] = 2;
        rpIds[2] = 3;
        uint64[] memory cs = new uint64[](3);
        cs[0] = 10;
        cs[1] = 10;
        cs[2] = 10;
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](2);
        votes[0] = _sign(pk1, 0, _counts(rpIds, cs));
        votes[1] = _sign(pk2, 0, _counts(rpIds, cs));
        billing.submitBillingVotes(0, votes);
        _closeVoting(0);

        // maxSteps=2 finalizes rp1, rp2 only.
        billing.finalizeEpochs(0, 2);
        assertEq(billing.outstandingDebt(1), 100);
        assertEq(billing.outstandingDebt(2), 100);
        assertEq(billing.outstandingDebt(3), 0, "rp3 not yet finalized");

        // Resume: finishes rp3 and closes the epoch.
        billing.finalizeEpochs(0, 100);
        assertEq(billing.outstandingDebt(3), 100);
    }

    function test_Finalize_votelessEpochSkipIsBounded() public {
        // Vote in epoch 0 and epoch 2; epoch 1 is voteless.
        _voteSingle(0, 1, 10, _pks2());
        _voteSingle(2, 1, 10, _pks2());
        _closeVoting(2);

        // maxSteps=1: finalizes epoch 0's rp1.
        billing.finalizeEpochs(2, 1);
        assertEq(billing.outstandingDebt(1), 100);

        // maxSteps=1: closes epoch 0, no new debt.
        billing.finalizeEpochs(2, 1);
        assertEq(billing.outstandingDebt(1), 100, "epoch 0 close should not accrue");

        // maxSteps=1: skips voteless epoch 1 (one close step), no new debt.
        billing.finalizeEpochs(2, 1);
        assertEq(billing.outstandingDebt(1), 100, "epoch 1 voteless skip should not accrue");

        // maxSteps=1: finalizes epoch 2's rp1.
        billing.finalizeEpochs(2, 1);
        assertEq(billing.outstandingDebt(1), 200);
    }

    function test_Finalize_revertsLatestClosedEpochTooLarge() public {
        billing = _deploy(0, 1, 1, PAYMENT, _tiers(100, 10, 5), REBATE);
        vm.warp(uint256(type(uint32).max) + 3);

        vm.expectRevert(IBillingContract.EpochTooLarge.selector);
        billing.finalizeEpochs(type(uint32).max, 100);
    }

    function test_Finalize_tierAcrossRebateBoundaryAndReset() public {
        // Tiers: first 100 @10, rest @5. Rebate period = 10 epochs.
        // epoch 0 (period 0): count 60 → 60*10 = 600. periodCount=60.
        _voteSingle(0, 1, 60, _pks2());
        // epoch 1 (period 0): count 60 → base 60→120: 40@10 + 20@5 = 400+100 = 500. periodCount=120.
        _voteSingle(1, 1, 60, _pks2());
        // epoch 10 (period 1): count 60 → period RESET, base 0→60: 60*10 = 600.
        _voteSingle(10, 1, 60, _pks2());
        _closeVoting(10);

        billing.finalizeEpochs(0, 100);
        assertEq(billing.outstandingDebt(1), 600, "epoch 0");

        billing.finalizeEpochs(1, 100);
        assertEq(billing.outstandingDebt(1), 1100, "epoch 1 crosses tier boundary");

        billing.finalizeEpochs(10, 100);
        // +600 (not +300) proves the rebate period reset at epoch 10.
        assertEq(billing.outstandingDebt(1), 1700, "epoch 10 resets rebate period");
    }

    function test_Finalize_scheduleChangeAppliesToUnfinalized() public {
        // No versioning: the tier schedule current at finalization prices every unfinalized epoch.
        // epoch 0 votes while the rate is 10.
        _voteSingle(0, 1, 10, _pks2());
        // Owner replaces the schedule (100@20, rest@10) before either epoch finalizes.
        billing.setTierSchedule(_tiers(100, 20, 10));
        // epoch 1 votes.
        _voteSingle(1, 2, 10, _pks2());
        _closeVoting(1);

        billing.finalizeEpochs(1, 100);
        // Both epochs are priced at the current rate 20 — the old rate is not pinned.
        assertEq(billing.outstandingDebt(1), 200, "epoch 0 re-priced at current rate 20");
        assertEq(billing.outstandingDebt(2), 200, "epoch 1 at current rate 20");
    }

    function test_PeerRotation_liveQuorumTracksNodeSet() public {
        // No snapshot: quorum is read live at finalization from the current node set.
        // First vote from node1 while n=3 (quorum 2).
        _openVoting(0);
        IBillingContract.SignedVoteChunk[] memory v1 = new IBillingContract.SignedVoteChunk[](1);
        v1[0] = _sign(pk1, 0, _one(1, 50));
        billing.submitBillingVotes(0, v1);

        // Grow the live set to 5 mid-window; quorum is now 3, computed live.
        address[] memory p = new address[](5);
        p[0] = node1;
        p[1] = node2;
        p[2] = node3;
        p[3] = node4;
        p[4] = node5;
        oprf.setPeers(p);

        // Second vote brings the count to 2, which misses the live quorum of 3.
        IBillingContract.SignedVoteChunk[] memory v2 = new IBillingContract.SignedVoteChunk[](1);
        v2[0] = _sign(pk2, 0, _one(1, 50));
        billing.submitBillingVotes(0, v2);

        _closeVoting(0);
        billing.finalizeEpochs(0, 100);
        assertEq(billing.outstandingDebt(1), 0, "2 votes miss the live quorum of 3");
    }

    ////////////////////////////////////////////////////////////
    //                    Payment + blocking                  //
    ////////////////////////////////////////////////////////////

    function _finalizeEpoch0Debt() internal returns (uint256 debt) {
        _voteSingle(0, 1, 50, _pks2());
        _closeVoting(0);
        billing.finalizeEpochs(0, 100);
        debt = billing.outstandingDebt(1);
    }

    function _fundPayer(uint256 amount) internal {
        feeToken.mint(payer, amount);
        vm.prank(payer);
        feeToken.approve(address(billing), amount);
    }

    function test_Pay_happy() public {
        uint256 debt = _finalizeEpoch0Debt();
        _fundPayer(debt);

        IBillingContract.RpPayment[] memory ps = new IBillingContract.RpPayment[](1);
        ps[0] = IBillingContract.RpPayment({rpId: 1, uptoEpoch: 0, maxAmount: type(uint256).max});

        vm.expectEmit(true, true, false, true, address(billing));
        emit IBillingContract.DebtPaid(1, payer, 0, debt);
        vm.prank(payer);
        billing.pay(ps);

        assertEq(billing.outstandingDebt(1), 0);
        assertEq(feeToken.balanceOf(feeRecipient), debt);
    }

    function test_Pay_slippageRevert() public {
        uint256 debt = _finalizeEpoch0Debt();
        _fundPayer(debt);

        IBillingContract.RpPayment[] memory ps = new IBillingContract.RpPayment[](1);
        ps[0] = IBillingContract.RpPayment({rpId: 1, uptoEpoch: 0, maxAmount: debt - 1});
        vm.prank(payer);
        vm.expectRevert(IBillingContract.DebtExceedsMax.selector);
        billing.pay(ps);
    }

    function test_Pay_skipsZeroDebt() public {
        // No finalized debt for rp 1; pay must be a no-op (idempotent, no revert).
        IBillingContract.RpPayment[] memory ps = new IBillingContract.RpPayment[](1);
        ps[0] = IBillingContract.RpPayment({rpId: 1, uptoEpoch: type(uint32).max, maxAmount: type(uint256).max});
        vm.prank(payer);
        billing.pay(ps);
        assertEq(feeToken.balanceOf(feeRecipient), 0);
    }

    function test_Pay_batchedMultiRp() public {
        // Finalize debt for rp 1 and rp 2 in epoch 0.
        _openVoting(0);
        uint64[] memory rpIds = new uint64[](2);
        rpIds[0] = 1;
        rpIds[1] = 2;
        uint64[] memory cs = new uint64[](2);
        cs[0] = 10;
        cs[1] = 20;
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](2);
        votes[0] = _sign(pk1, 0, _counts(rpIds, cs));
        votes[1] = _sign(pk2, 0, _counts(rpIds, cs));
        billing.submitBillingVotes(0, votes);
        _closeVoting(0);
        billing.finalizeEpochs(0, 100);

        uint256 debt1 = billing.outstandingDebt(1); // 10*10
        uint256 debt2 = billing.outstandingDebt(2); // 20*10
        assertEq(debt1, 100);
        assertEq(debt2, 200);
        _fundPayer(debt1 + debt2);

        IBillingContract.RpPayment[] memory ps = new IBillingContract.RpPayment[](2);
        ps[0] = IBillingContract.RpPayment({rpId: 1, uptoEpoch: 0, maxAmount: type(uint256).max});
        ps[1] = IBillingContract.RpPayment({rpId: 2, uptoEpoch: 0, maxAmount: type(uint256).max});
        vm.prank(payer);
        billing.pay(ps);

        assertEq(billing.outstandingDebt(1), 0);
        assertEq(billing.outstandingDebt(2), 0);
        assertEq(feeToken.balanceOf(feeRecipient), debt1 + debt2);
    }

    /// @dev pay must NOT finalize; a closed-but-unfinalized epoch yields no payable debt.
    function test_Pay_doesNotFinalize() public {
        _voteSingle(0, 1, 50, _pks2());
        _closeVoting(0);
        // Deliberately do not finalize.
        IBillingContract.RpPayment[] memory ps = new IBillingContract.RpPayment[](1);
        ps[0] = IBillingContract.RpPayment({rpId: 1, uptoEpoch: 0, maxAmount: type(uint256).max});
        vm.prank(payer);
        billing.pay(ps);
        assertEq(feeToken.balanceOf(feeRecipient), 0, "pay should not have finalized/charged");
    }

    function test_IsBlocked_lifecycle() public {
        uint256 debt = _finalizeEpoch0Debt();
        uint64 due = billing.epochEnd(0) + VOTING + PAYMENT;

        // Within the payment window: not blocked.
        vm.warp(due);
        assertFalse(billing.is_blocked(1));

        // Past the payment window: blocked.
        vm.warp(due + 1);
        assertTrue(billing.is_blocked(1));

        // Pay clears the block.
        _fundPayer(debt);
        IBillingContract.RpPayment[] memory ps = new IBillingContract.RpPayment[](1);
        ps[0] = IBillingContract.RpPayment({rpId: 1, uptoEpoch: 0, maxAmount: type(uint256).max});
        vm.prank(payer);
        billing.pay(ps);
        assertFalse(billing.is_blocked(1));
    }

    function test_IsBlocked_advancesToNextUnpaidEpochAfterPartialPayment() public {
        _voteSingle(0, 1, 50, _pks2());
        _voteSingle(1, 1, 50, _pks2());
        _closeVoting(1);
        billing.finalizeEpochs(1, 100);

        uint256 epoch0Debt = 500;
        uint256 epoch1Debt = 500;
        assertEq(billing.outstandingDebt(1), epoch0Debt + epoch1Debt);

        uint64 epoch0Due = billing.epochEnd(0) + VOTING + PAYMENT;
        uint64 epoch1Due = billing.epochEnd(1) + VOTING + PAYMENT;
        vm.warp(epoch0Due + 1);
        assertTrue(billing.is_blocked(1), "epoch 0 is overdue");

        _fundPayer(epoch0Debt);
        IBillingContract.RpPayment[] memory ps = new IBillingContract.RpPayment[](1);
        ps[0] = IBillingContract.RpPayment({rpId: 1, uptoEpoch: 0, maxAmount: epoch0Debt});
        vm.prank(payer);
        billing.pay(ps);

        assertEq(billing.outstandingDebt(1), epoch1Debt);
        assertFalse(billing.is_blocked(1), "epoch 1 is unpaid but not due yet");

        vm.warp(epoch1Due + 1);
        assertTrue(billing.is_blocked(1), "epoch 1 becomes the blocking epoch");
    }

    function test_IsBlocked_falseWithoutDebt() public view {
        assertFalse(billing.is_blocked(999));
    }

    ////////////////////////////////////////////////////////////
    //                     Owner functions                    //
    ////////////////////////////////////////////////////////////

    function test_SetTierSchedule_ownerOnly() public {
        vm.prank(payer);
        vm.expectRevert();
        billing.setTierSchedule(_tiers(100, 20, 10));
    }

    function test_SetTierSchedule_revertsInvalidRatesNotDecreasing() public {
        IBillingContract.Tier[] memory t = new IBillingContract.Tier[](2);
        t[0] = IBillingContract.Tier({upTo: 100, rate: 5});
        t[1] = IBillingContract.Tier({upTo: type(uint256).max, rate: 10}); // not decreasing
        vm.expectRevert(IBillingContract.InvalidTierSchedule.selector);
        billing.setTierSchedule(t);
    }

    function test_SetTierSchedule_revertsLastNotMax() public {
        IBillingContract.Tier[] memory t = new IBillingContract.Tier[](1);
        t[0] = IBillingContract.Tier({upTo: 100, rate: 10}); // last upTo != max
        vm.expectRevert(IBillingContract.InvalidTierSchedule.selector);
        billing.setTierSchedule(t);
    }

    function test_SetTiming_revertsInvariant() public {
        vm.expectRevert(IBillingContract.InvalidTiming.selector);
        billing.setTiming(EPOCH_LEN, EPOCH_LEN + 1, PAYMENT);
    }

    function test_SetTiming_ownerOnly() public {
        vm.prank(payer);
        vm.expectRevert();
        billing.setTiming(EPOCH_LEN, VOTING, PAYMENT);
    }

    ////////////////////////////////////////////////////////////
    //               Timing changes (era history)             //
    ////////////////////////////////////////////////////////////

    function test_GetTiming_initialEra() public view {
        (uint64 len, uint64 vw, uint64 pw, uint32 eraStartEpoch, uint64 eraStartTime) = billing.getTiming();
        assertEq(len, EPOCH_LEN);
        assertEq(vw, VOTING);
        assertEq(pw, PAYMENT);
        assertEq(eraStartEpoch, 0);
        assertEq(eraStartTime, GENESIS);
        assertEq(billing.getEras().length, 1);
    }

    function test_SetTiming_backlogFinalizesAfterChange() public {
        // Epoch 0 is closed but not finalized; epoch 1's window is open with votes in flight.
        _voteSingle(0, 1, 50, _pks2());
        _voteSingle(1, 1, 50, _pks2()); // warps to epochEnd(1): epoch 0 is now closed

        // The change succeeds despite the backlog; the new era starts at epoch 3.
        billing.setTiming(EPOCH_LEN, VOTING, PAYMENT);
        (,,, uint32 eraStartEpoch, uint64 eraStartTime) = billing.getTiming();
        assertEq(eraStartEpoch, 3);
        assertEq(eraStartTime, GENESIS + 300);

        // Epoch 0 was already closed at the change: it finalizes immediately, undelayed.
        billing.finalizeEpochs(type(uint32).max, 100);
        assertEq(billing.outstandingDebt(1), 500, "closed backlog finalizes right away");

        // Epoch 1 finalizes at its exact historic close, before the first new-era window closes.
        vm.warp(eraStartTime);
        billing.finalizeEpochs(type(uint32).max, 100);
        assertEq(billing.outstandingDebt(1), 1000, "epoch 0 (500) + epoch 1 (500)");

        // Epoch 0's deadline is its historic one (GENESIS + 400), unmoved by the change.
        vm.warp(GENESIS + 400);
        assertFalse(billing.is_blocked(1)); // exactly at the deadline
        vm.warp(GENESIS + 401);
        assertTrue(billing.is_blocked(1), "historic deadline unchanged by the change");
    }

    function test_SetTiming_openWindowUnaffectedByChange() public {
        // Epoch 0's window is open (continuous voting) with no votes in yet; the change needs no
        // precondition and does not touch the window.
        vm.warp(GENESIS + 150);
        billing.setTiming(200, 150, 300); // new era from epoch 2 (GENESIS + 200)

        // Nodes still vote for epoch 0 as if nothing happened...
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](2);
        votes[0] = _sign(pk1, 0, _one(1, 50));
        votes[1] = _sign(pk2, 0, _one(1, 50));
        billing.submitBillingVotes(0, votes);

        // ...and the window closes at its historic time (era-0 votingWindow), not the new one.
        vm.warp(GENESIS + 200);
        IBillingContract.SignedVoteChunk[] memory late = new IBillingContract.SignedVoteChunk[](1);
        late[0] = _sign(pk3, 0, _one(1, 70));
        vm.expectRevert(IBillingContract.VotingWindowClosed.selector);
        billing.submitBillingVotes(0, late);
    }

    function test_SetTiming_atGenesisStartsEraAtEpochOne() public {
        // At genesis, epoch 0 is in flight: the new era starts right after it.
        billing.setTiming(200, 100, PAYMENT);
        (,,, uint32 eraStartEpoch, uint64 eraStartTime) = billing.getTiming();
        assertEq(eraStartEpoch, 1);
        assertEq(eraStartTime, GENESIS + EPOCH_LEN); // in-flight epoch 0 keeps its boundary
        assertEq(billing.epochEnd(1), GENESIS + EPOCH_LEN + 200);
    }

    function test_SetTiming_pendingEraIsUpdatedInPlace() public {
        billing.setTiming(200, 100, PAYMENT); // era from epoch 1 (GENESIS + EPOCH_LEN)
        // The pending era has not started: a second change updates it in place.
        billing.setTiming(300, 200, PAYMENT);
        (uint64 len, uint64 vw,, uint32 eraStartEpoch, uint64 eraStartTime) = billing.getTiming();
        assertEq(len, 300);
        assertEq(vw, 200);
        assertEq(eraStartEpoch, 1);
        assertEq(eraStartTime, GENESIS + EPOCH_LEN);
        assertEq(billing.epochEnd(1), GENESIS + EPOCH_LEN + 300);
        assertEq(billing.getEras().length, 2, "no third era for an in-place update");
    }

    function test_SetTiming_lateVotesSurviveEraChange() public {
        // Two of three nodes voted for epoch 0; laggard node3 has not.
        _voteSingle(0, 1, 50, _pks2()); // now = GENESIS + 100

        vm.expectEmit(false, false, false, true, address(billing));
        emit IBillingContract.TimingUpdated(200, 150, 300, 2, GENESIS + 200);
        billing.setTiming(200, 150, 300);

        // Historic and new boundaries: epoch 0 and the in-flight epoch 1 keep theirs; epoch 2 on
        // uses the new length.
        assertEq(billing.epochEnd(0), GENESIS + 100);
        assertEq(billing.epochEnd(1), GENESIS + 200);
        assertEq(billing.epochEnd(2), GENESIS + 400);

        // The laggard's vote still lands: epoch 0's window is open until its historic close.
        vm.warp(GENESIS + 199);
        IBillingContract.SignedVoteChunk[] memory late = new IBillingContract.SignedVoteChunk[](1);
        late[0] = _sign(pk3, 0, _one(1, 80));
        billing.submitBillingVotes(0, late);

        // Epoch 1's window opens at the preserved boundary, governed by the new votingWindow.
        _voteSingle(1, 1, 50, _pks2()); // warps to GENESIS + 200
        vm.warp(GENESIS + 200 + 150);

        // Epoch 0 finalizes over all three votes [50, 50, 80] -> median 50; nothing was lost.
        billing.finalizeEpochs(type(uint32).max, 100);
        assertEq(billing.outstandingDebt(1), 1000, "epoch 0 (500) + epoch 1 (500)");
    }

    function test_SetTiming_preservesHistoricDeadlines() public {
        _finalizeEpoch0Debt(); // due at epochEnd(0) + VOTING + PAYMENT = GENESIS + 400
        vm.warp(GENESIS + 401);
        assertTrue(billing.is_blocked(1), "epoch 0 debt is overdue");

        // The change starts a new era but moves no existing deadline: the RP stays blocked.
        billing.setTiming(200, 150, 300);
        assertTrue(billing.is_blocked(1), "historic deadline is not affected by the change");
    }

    function test_LatestClosed_capsAtRegimeBoundary() public {
        // Fresh deployment with a short voting window (40 < epoch length 100), then a change to a
        // wider window (90): between the old close cadence and the new regime's first close, the
        // boundary epoch's window is still open and must not be reported closed.
        billing = _deploy(GENESIS, 100, 40, PAYMENT, _tiers(100, 10, 5), REBATE);
        vm.warp(GENESIS + 250); // inside epoch 2, no window open
        billing.setTiming(100, 90, PAYMENT); // era 1 from epoch 3 (GENESIS + 300)

        // Epoch 2's window opens at GENESIS + 300 and closes at +390 (new-era votingWindow).
        vm.warp(GENESIS + 340);
        IBillingContract.SignedVoteChunk[] memory votes = new IBillingContract.SignedVoteChunk[](2);
        votes[0] = _sign(pk1, 2, _one(1, 50));
        votes[1] = _sign(pk2, 2, _one(1, 50));
        billing.submitBillingVotes(2, votes);

        // The old-era close cadence alone would report epoch 2 closed at +340; the regime cap
        // keeps it open, so finalization must not consume it mid-window.
        billing.finalizeEpochs(type(uint32).max, 100);
        assertEq(billing.outstandingDebt(1), 0, "epoch 2 must not finalize mid-window");

        vm.warp(GENESIS + 390);
        billing.finalizeEpochs(type(uint32).max, 100);
        assertEq(billing.outstandingDebt(1), 500, "epoch 2 finalizes at its true close");
    }

    function test_EpochEnd_historicAcrossEras() public {
        vm.warp(GENESIS + 150);
        billing.setTiming(200, 150, 300); // era 1 from epoch 2 (GENESIS + 200)
        vm.warp(GENESIS + 450); // inside epoch 3 (era 1)
        billing.setTiming(400, 300, 500); // era 2 from epoch 4 (GENESIS + 600)

        // Every epoch keeps the boundary of the era it belongs to.
        assertEq(billing.epochEnd(0), GENESIS + 100); // era 0
        assertEq(billing.epochEnd(1), GENESIS + 200); // era 0 (its last epoch)
        assertEq(billing.epochEnd(2), GENESIS + 400); // era 1
        assertEq(billing.epochEnd(3), GENESIS + 600); // era 1 (its last epoch)
        assertEq(billing.epochEnd(4), GENESIS + 1000); // era 2

        IBillingContract.TimingEra[] memory eras = billing.getEras();
        assertEq(eras.length, 3);
        assertEq(eras[1].startEpoch, 2);
        assertEq(eras[2].startTime, GENESIS + 600);
    }

    function test_SetRebatePeriodEpochs() public {
        billing.setRebatePeriodEpochs(20);
        assertEq(billing.getRebatePeriodEpochs(), 20);
    }

    function test_SetRebatePeriodEpochs_revertsZero() public {
        vm.expectRevert(IBillingContract.InvalidTiming.selector);
        billing.setRebatePeriodEpochs(0);
    }

    function test_UpdateOprfKeyRegistry_ownerOnly() public {
        vm.prank(payer);
        vm.expectRevert();
        billing.updateOprfKeyRegistry(address(0xdead));
    }

    function test_UpdateOprfKeyRegistry_revertsZeroAddress() public {
        vm.expectRevert(WorldIDBase.ZeroAddress.selector);
        billing.updateOprfKeyRegistry(address(0));
    }
}
