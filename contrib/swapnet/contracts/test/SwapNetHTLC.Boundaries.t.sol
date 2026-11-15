// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../SwapNetHTLC.sol";
import "./utils/Base.sol";
import "./utils/Actors.sol";
import "./utils/Tokens.sol";

/// Unit tests for every external entry point of SwapNetHTLC and its exact boundaries.
contract SwapNetHTLCBoundariesTest is Base {
    SwapNetHTLC h;
    address constant FUNDER = address(0xF0D0); // funder, refundTo
    address constant CLAIMANT = address(0xC1A1);     // claimTo
    address constant RELAY = address(0xBEEF);  // unrelated relayer
    bytes32 constant SECRET = bytes32(uint256(42));
    bytes32 constant SALT = bytes32(uint256(1));
    uint256 constant T0 = 1_800_000_000;
    bytes32 HL;

    function setUp() public {
        vm.warp(T0);
        h = new SwapNetHTLC();
        HL = sha256(abi.encodePacked(SECRET));
        vm.deal(FUNDER, 100 ether);
        vm.deal(RELAY, 1 ether);
    }

    // ---------- helpers ----------
    function lockAs(address funder, bytes32 salt, bytes32 hl, address claimTo, uint64 refundAt, uint256 value)
        internal returns (bytes32 id)
    {
        vm.prank(funder);
        id = h.lockNative{value: value}(salt, hl, claimTo, refundAt);
    }

    function lockDefault() internal returns (bytes32 id, uint64 refundAt) {
        refundAt = uint64(block.timestamp + 4 hours);
        id = lockAs(FUNDER, SALT, HL, CLAIMANT, refundAt, 1 ether);
    }

    function stateOf(bytes32 id) internal view returns (SwapNetHTLC.State st) {
        (,,,,,, st) = h.getSwap(id);
    }

    // ---------- constants and shape ----------
    function test_constants() public view {
        eq(h.MIN_LOCK(), 1 hours, "MIN_LOCK");
        eq(h.MAX_LOCK(), 30 days, "MAX_LOCK");
    }

    function test_plainEthTransferRejected() public {
        vm.prank(FUNDER);
        (bool sent,) = address(h).call{value: 1 ether}("");
        ok(!sent, "contract must not accept plain ETH");
        vm.prank(FUNDER);
        (sent,) = address(h).call{value: 1 ether}(hex"deadbeef");
        ok(!sent, "unknown selector must revert");
    }

    function test_lockTokenIsNotPayable() public {
        StdToken t = new StdToken();
        t.mint(FUNDER, 1);
        vm.prank(FUNDER); t.approve(address(h), 1);
        bytes memory data = abi.encodeCall(SwapNetHTLC.lockToken,
            (SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(t), 1));
        vm.prank(FUNDER);
        (bool sent, bytes memory ret) = address(h).call{value: 1}(data);
        ok(!sent && ret.length == 0, "non-payable check rejects attached ETH before any logic");
        vm.prank(FUNDER);
        (sent,) = address(h).call(data);
        ok(sent, "the same call without ETH succeeds");
    }

    // ---------- lockNative: every InvalidTerms branch ----------
    function test_lock_rejectsZeroHashlock() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, bytes32(0), CLAIMANT, uint64(block.timestamp + 2 hours), 1 ether);
    }

    function test_lock_rejectsZeroClaimTo() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, address(0), uint64(block.timestamp + 2 hours), 1 ether);
    }

    function test_lock_rejectsContractAsClaimTo() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, address(h), uint64(block.timestamp + 2 hours), 1 ether);
    }

    function test_lock_rejectsFunderAsClaimTo() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, FUNDER, uint64(block.timestamp + 2 hours), 1 ether);
    }

    function test_lock_rejectsZeroValue() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), 0);
    }

    function test_lock_minLockBoundary() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp + 1 hours - 1), 1 ether);
        bytes32 id = lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp + 1 hours), 1 ether);
        ok(stateOf(id) == SwapNetHTLC.State.Locked, "exact MIN_LOCK accepted");
    }

    function test_lock_maxLockBoundary() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp + 30 days + 1), 1 ether);
        bytes32 id = lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp + 30 days), 1 ether);
        ok(stateOf(id) == SwapNetHTLC.State.Locked, "exact MAX_LOCK accepted");
    }

    function test_lock_rejectsPastAndNowRefundAt() public {
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp), 1 ether);
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp - 1), 1 ether);
    }

    function test_lock_recordsExactTerms() public {
        uint64 refundAt = uint64(block.timestamp + 5 hours);
        bytes32 expectId = h.computeId(FUNDER, SALT);
        bytes32 id = lockAs(FUNDER, SALT, HL, CLAIMANT, refundAt, 1.5 ether);
        eq(id, expectId, "returned id");
        (bytes32 hl, address token, address refundTo, address claimTo, uint256 amount, uint64 ra, SwapNetHTLC.State st) = h.getSwap(id);
        eq(hl, HL, "hashlock"); eq(token, address(0), "token"); eq(refundTo, FUNDER, "refundTo is msg.sender");
        eq(claimTo, CLAIMANT, "claimTo"); eq(amount, 1.5 ether, "amount"); eq(uint256(ra), uint256(refundAt), "refundAt");
        ok(st == SwapNetHTLC.State.Locked, "state");
        eq(address(h).balance, 1.5 ether, "contract holds value");
    }

    function test_lock_eventLayout() public {
        uint64 refundAt = uint64(block.timestamp + 5 hours);
        vm.recordLogs();
        bytes32 id = lockAs(FUNDER, SALT, HL, CLAIMANT, refundAt, 1.5 ether);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        // Layout the off-chain driver relies on: topics = [sig, id, refundTo, claimTo].
        eq(logs.length, 1, "one log");
        eq(logs[0].emitter, address(h), "emitter");
        eq(logs[0].topics.length, 4, "topics");
        eq(logs[0].topics[0], keccak256("Locked(bytes32,bytes32,address,address,address,uint256,uint64)"), "Locked sig");
        eq(logs[0].topics[1], id, "topic1 = id");
        eq(logs[0].topics[2], bytes32(uint256(uint160(FUNDER))), "topic2 = refundTo");
        eq(logs[0].topics[3], bytes32(uint256(uint160(CLAIMANT))), "topic3 = claimTo");
        (bytes32 dHl, address dTok, uint256 dAmt, uint64 dRa) = abi.decode(logs[0].data, (bytes32, address, uint256, uint64));
        eq(dHl, HL, "data hashlock"); eq(dTok, address(0), "data token"); eq(dAmt, 1.5 ether, "data amount"); eq(uint256(dRa), uint256(refundAt), "data refundAt");
    }

    function test_lock_duplicateIdRejectedEvenWithOtherTerms() public {
        (bytes32 id,) = lockDefault();
        vm.expectRevert(SwapNetHTLC.AlreadyExists.selector);
        lockAs(FUNDER, SALT, bytes32(uint256(7)), RELAY, uint64(block.timestamp + 9 hours), 2 ether);
        // Original terms untouched.
        (bytes32 hl,,, address claimTo, uint256 amount,,) = h.getSwap(id);
        eq(hl, HL, "hashlock kept"); eq(claimTo, CLAIMANT, "claimTo kept"); eq(amount, 1 ether, "amount kept");
    }

    function test_lock_sameSaltOtherFunderIsIndependent() public {
        (bytes32 idA,) = lockDefault();
        vm.deal(RELAY, 5 ether);
        bytes32 idR = lockAs(RELAY, SALT, HL, CLAIMANT, uint64(block.timestamp + 4 hours), 1 ether);
        ok(idA != idR, "sender-scoped ids differ");
        (,, address refundTo,,,,) = h.getSwap(idA);
        eq(refundTo, FUNDER, "third party cannot squat or overwrite the funder's id");
    }

    function test_lock_idCannotBeReusedAfterClaimOrRefund() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        h.claim(id, SECRET);
        vm.expectRevert(SwapNetHTLC.AlreadyExists.selector);
        lockAs(FUNDER, SALT, HL, CLAIMANT, uint64(block.timestamp + 4 hours), 1 ether);

        bytes32 salt2 = bytes32(uint256(2));
        bytes32 id2 = lockAs(FUNDER, salt2, HL, CLAIMANT, refundAt, 1 ether);
        vm.warp(refundAt);
        h.refund(id2);
        vm.expectRevert(SwapNetHTLC.AlreadyExists.selector);
        lockAs(FUNDER, salt2, HL, CLAIMANT, uint64(block.timestamp + 4 hours), 1 ether);
    }

    // ---------- computeId binding ----------
    function test_id_bindsChainId() public {
        bytes32 a = h.computeId(FUNDER, SALT);
        vm.chainId(5);
        bytes32 b = h.computeId(FUNDER, SALT);
        ok(a != b, "chain id is bound");
    }

    function test_id_bindsContractAddress() public {
        SwapNetHTLC other = new SwapNetHTLC();
        ok(h.computeId(FUNDER, SALT) != other.computeId(FUNDER, SALT), "contract address is bound");
    }

    function test_id_bindsFunderAndSalt() public view {
        bytes32 a = h.computeId(FUNDER, SALT);
        ok(a != h.computeId(CLAIMANT, SALT), "funder bound");
        ok(a != h.computeId(FUNDER, bytes32(uint256(2))), "salt bound");
    }

    /// The Python driver builds the id as abi_word(chain) || abi_word(contract) || abi_word(funder) || salt
    /// (swapnet/evm.py lock_id). That is exactly abi.encode of the same four values.
    function test_id_matchesDriverByteLayout() public view {
        bytes32 driverStyle = keccak256(abi.encodePacked(
            uint256(block.chainid), uint256(uint160(address(h))), uint256(uint160(FUNDER)), SALT));
        eq(h.computeId(FUNDER, SALT), driverStyle, "driver layout");
    }

    // ---------- claim ----------
    function test_claim_absentId() public {
        vm.expectRevert(SwapNetHTLC.NotLocked.selector);
        h.claim(keccak256("nothing"), SECRET);
    }

    function test_claim_wrongPreimage() public {
        (bytes32 id,) = lockDefault();
        vm.expectRevert(SwapNetHTLC.InvalidPreimage.selector);
        h.claim(id, bytes32(uint256(43)));
    }

    function test_claim_keccakPreimageDoesNotWork() public {
        // Hashlocks are SHA-256 on both chains; a Keccak hashlock is unclaimable by design.
        uint64 refundAt = uint64(block.timestamp + 4 hours);
        bytes32 id = lockAs(FUNDER, SALT, keccak256(abi.encodePacked(SECRET)), CLAIMANT, refundAt, 1 ether);
        vm.expectRevert(SwapNetHTLC.InvalidPreimage.selector);
        h.claim(id, SECRET);
    }

    function test_claim_lastSecondBeforeRefundAt() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        vm.warp(refundAt - 1);
        h.claim(id, SECRET);
        ok(stateOf(id) == SwapNetHTLC.State.Claimed, "claimed at refundAt-1");
    }

    function test_claim_atRefundAtIsTooLate() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        vm.warp(refundAt);
        vm.expectRevert(SwapNetHTLC.TooLate.selector);
        h.claim(id, SECRET);
    }

    function test_claim_byRelayerCreditsClaimToOnly() public {
        (bytes32 id,) = lockDefault();
        vm.prank(RELAY);
        h.claim(id, SECRET);
        eq(h.credits(CLAIMANT, address(0)), 1 ether, "claimTo credited");
        eq(h.credits(RELAY, address(0)), 0, "relayer not credited");
        eq(h.credits(FUNDER, address(0)), 0, "funder not credited");
        eq(address(h).balance, 1 ether, "claim moves no ETH");
    }

    function test_claim_emitsPreimageInDriverLayout() public {
        (bytes32 id,) = lockDefault();
        vm.recordLogs();
        h.claim(id, SECRET);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        eq(logs.length, 1, "one log");
        eq(logs[0].topics.length, 2, "topics");
        eq(logs[0].topics[0], keccak256("Claimed(bytes32,bytes32)"), "Claimed sig");
        eq(logs[0].topics[1], id, "topic1 = id");
        eq(logs[0].data.length, 32, "data is the 32-byte preimage");
        eq(abi.decode(logs[0].data, (bytes32)), SECRET, "preimage");
    }

    function test_claim_twice() public {
        (bytes32 id,) = lockDefault();
        h.claim(id, SECRET);
        vm.expectRevert(SwapNetHTLC.NotLocked.selector);
        h.claim(id, SECRET);
        eq(h.credits(CLAIMANT, address(0)), 1 ether, "credited once");
    }

    function test_claim_afterRefund() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        vm.warp(refundAt);
        h.refund(id);
        vm.warp(refundAt - 10); // even if time could go back, state blocks it
        vm.expectRevert(SwapNetHTLC.NotLocked.selector);
        h.claim(id, SECRET);
    }

    // ---------- refund ----------
    function test_refund_absentId() public {
        vm.expectRevert(SwapNetHTLC.NotLocked.selector);
        h.refund(keccak256("nothing"));
    }

    function test_refund_lastSecondTooEarly() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        vm.warp(refundAt - 1);
        vm.expectRevert(SwapNetHTLC.TooEarly.selector);
        h.refund(id);
    }

    function test_refund_atRefundAt() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        vm.warp(refundAt);
        vm.recordLogs();
        h.refund(id);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        ok(stateOf(id) == SwapNetHTLC.State.Refunded, "refunded");
        eq(h.credits(FUNDER, address(0)), 1 ether, "funder credited");
        eq(logs.length, 1, "one log");
        eq(logs[0].topics[0], keccak256("Refunded(bytes32)"), "Refunded sig");
        eq(logs[0].topics[1], id, "topic1 = id");
    }

    function test_refund_byRelayerCreditsFunderOnly() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        vm.warp(refundAt + 7 days);
        vm.prank(RELAY);
        h.refund(id);
        eq(h.credits(FUNDER, address(0)), 1 ether, "funder credited");
        eq(h.credits(RELAY, address(0)), 0, "relayer not credited");
        eq(h.credits(CLAIMANT, address(0)), 0, "claimTo not credited");
    }

    function test_refund_twiceAndAfterClaim() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        vm.warp(refundAt);
        h.refund(id);
        vm.expectRevert(SwapNetHTLC.NotLocked.selector);
        h.refund(id);

        bytes32 id2 = lockAs(FUNDER, bytes32(uint256(9)), HL, CLAIMANT, uint64(block.timestamp + 2 hours), 1 ether);
        h.claim(id2, SECRET);
        vm.warp(block.timestamp + 3 hours);
        vm.expectRevert(SwapNetHTLC.NotLocked.selector);
        h.refund(id2);
        eq(h.credits(FUNDER, address(0)), 1 ether, "only the first refund credited");
    }

    /// Around the deadline exactly one of claim/refund is possible at every second.
    function test_claimRefundExclusiveAroundDeadline() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        for (uint256 t = refundAt - 3; t <= refundAt + 3; t++) {
            uint256 snap = vm.snapshotState();
            vm.warp(t);
            (bool c,) = address(h).call(abi.encodeCall(SwapNetHTLC.claim, (id, SECRET)));
            vm.revertToState(snap);
            snap = vm.snapshotState();
            vm.warp(t);
            (bool r,) = address(h).call(abi.encodeCall(SwapNetHTLC.refund, (id)));
            vm.revertToState(snap);
            ok(c != r, "exactly one path open");
            ok(c == (t < refundAt), "claim iff t < refundAt");
        }
    }

    // ---------- withdraw ----------
    function claimed() internal returns (bytes32 id) {
        (id,) = lockDefault();
        h.claim(id, SECRET);
    }

    function test_withdraw_rejectsZeroAndSelfRecipient() public {
        claimed();
        vm.startPrank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        h.withdrawTo(address(0), payable(address(0)));
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        h.withdrawTo(address(0), payable(address(h)));
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        h.withdrawAmount(address(0), payable(address(h)), 1);
        vm.stopPrank();
        eq(h.credits(CLAIMANT, address(0)), 1 ether, "credit kept");
    }

    function test_withdraw_noCreditCases() public {
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawTo(address(0), payable(CLAIMANT));
        claimed();
        vm.startPrank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawAmount(address(0), payable(CLAIMANT), 0);
        vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawAmount(address(0), payable(CLAIMANT), 1 ether + 1);
        vm.stopPrank();
        vm.prank(RELAY);
        vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawTo(address(0), payable(RELAY));
    }

    function test_withdraw_exactCreditToThirdParty() public {
        claimed();
        address payable dest = payable(address(0xD357));
        vm.recordLogs();
        vm.prank(CLAIMANT);
        h.withdrawAmount(address(0), dest, 1 ether);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        eq(dest.balance, 1 ether, "paid to chosen address");
        eq(h.credits(CLAIMANT, address(0)), 0, "credit cleared");
        eq(address(h).balance, 0, "contract drained");
        eq(logs[0].topics[0], keccak256("Withdrawn(address,address,address,uint256)"), "Withdrawn sig");
        eq(logs[0].topics[1], bytes32(uint256(uint160(CLAIMANT))), "owner indexed");
        eq(logs[0].topics[2], bytes32(0), "token indexed");
        (address to, uint256 amt) = abi.decode(logs[0].data, (address, uint256));
        eq(to, dest, "to"); eq(amt, 1 ether, "amount");
    }

    function test_withdraw_revertingRecipientKeepsCredit() public {
        claimed();
        RevertingReceiver bad = new RevertingReceiver();
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.TransferFailed.selector);
        h.withdrawTo(address(0), payable(address(bad)));
        eq(h.credits(CLAIMANT, address(0)), 1 ether, "credit restored by revert");
        vm.prank(CLAIMANT);
        h.withdrawTo(address(0), payable(CLAIMANT));
        eq(CLAIMANT.balance, 1 ether, "retry to a working address");
    }

    function test_withdraw_reentryFromRecipientBlocked() public {
        // The recipient's hook tries each state-changing entry point; every one must hit the lock.
        bytes32 id2 = lockAs(FUNDER, bytes32(uint256(5)), HL, CLAIMANT, uint64(block.timestamp + 4 hours), 1 ether);
        claimed();
        ReentrantReceiver rr = new ReentrantReceiver(h);
        bytes[6] memory calls = [
            abi.encodeCall(SwapNetHTLC.withdrawAmount, (address(0), payable(address(rr)), 1)),
            abi.encodeCall(SwapNetHTLC.withdrawTo, (address(0), payable(address(rr)))),
            abi.encodeCall(SwapNetHTLC.claim, (id2, SECRET)),
            abi.encodeCall(SwapNetHTLC.refund, (id2)),
            abi.encodeCall(SwapNetHTLC.lockNative, (bytes32(uint256(77)), HL, CLAIMANT, uint64(block.timestamp + 2 hours))),
            abi.encodeCall(SwapNetHTLC.lockToken, (bytes32(uint256(78)), HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(0x1234), 1))
        ];
        for (uint256 i = 0; i < calls.length; i++) {
            rr.setCall(calls[i]);
            vm.prank(CLAIMANT);
            h.withdrawAmount(address(0), payable(address(rr)), 0.1 ether);
            ok(!rr.reentryOk(), "re-entry must fail");
            eq(bytes32(rr.reentryRet()), bytes32(SwapNetHTLC.Reentrant.selector), "with Reentrant");
        }
        eq(h.credits(CLAIMANT, address(0)), 0.4 ether, "six 0.1 withdrawals");
        ok(stateOf(id2) == SwapNetHTLC.State.Locked, "other swap untouched");
        eq(vm.load(address(h), bytes32(uint256(2))), bytes32(0), "lock released");
    }

    function test_withdraw_partialCreditsAcrossSwaps() public {
        claimed();
        bytes32 id2 = lockAs(FUNDER, bytes32(uint256(3)), HL, CLAIMANT, uint64(block.timestamp + 4 hours), 2 ether);
        h.claim(id2, SECRET);
        eq(h.credits(CLAIMANT, address(0)), 3 ether, "aggregated");
        vm.prank(CLAIMANT); h.withdrawAmount(address(0), payable(CLAIMANT), 1 ether);
        eq(h.credits(CLAIMANT, address(0)), 2 ether, "remaining");
        vm.prank(CLAIMANT); h.withdrawTo(address(0), payable(CLAIMANT));
        eq(CLAIMANT.balance, 3 ether, "all paid");
        eq(address(h).balance, 0, "drained");
    }

    function test_contractFunderCanRecoverRefund() public {
        ContractFunder cf = new ContractFunder(h);
        vm.deal(address(this), 1 ether);
        uint64 refundAt = uint64(block.timestamp + 2 hours);
        bytes32 id = cf.lock{value: 1 ether}(SALT, HL, CLAIMANT, refundAt);
        vm.warp(refundAt);
        h.refund(id);
        eq(h.credits(address(cf), address(0)), 1 ether, "contract funder credited");
        cf.withdrawTo(payable(FUNDER));
        eq(h.credits(address(cf), address(0)), 0, "withdrawn");
    }

    function test_forcedEthCreatesNoCredit() public {
        claimed();
        vm.deal(address(h), address(h).balance + 3 ether); // ETH arriving without a call
        eq(address(h).balance, 4 ether, "forced ETH arrives");
        eq(h.credits(CLAIMANT, address(0)), 1 ether, "credits unchanged");
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawAmount(address(0), payable(CLAIMANT), 2 ether);
        vm.prank(CLAIMANT);
        h.withdrawTo(address(0), payable(CLAIMANT));
        eq(address(h).balance, 3 ether, "forced ETH is inert dust");
    }

    // ---------- getSwap layout and driver ABI ----------
    function test_getSwapIsSevenWordsAsDriverParses() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        (bool s, bytes memory raw) = address(h).staticcall(abi.encodeWithSignature("getSwap(bytes32)", id));
        ok(s, "call"); eq(raw.length, 224, "7 words");
        bytes32[7] memory w = abi.decode(raw, (bytes32[7]));
        eq(w[0], HL, "w0 hashlock");
        eq(w[1], bytes32(0), "w1 token");
        eq(w[2], bytes32(uint256(uint160(FUNDER))), "w2 refundTo");
        eq(w[3], bytes32(uint256(uint160(CLAIMANT))), "w3 claimTo");
        eq(uint256(w[4]), 1 ether, "w4 amount");
        eq(uint256(w[5]), uint256(refundAt), "w5 refundAt");
        eq(uint256(w[6]), 1, "w6 state Locked=1");
        h.claim(id, SECRET);
        (, raw) = address(h).staticcall(abi.encodeWithSignature("getSwap(bytes32)", id));
        w = abi.decode(raw, (bytes32[7]));
        eq(uint256(w[6]), 2, "Claimed=2, terms kept");
        eq(w[0], HL, "terms kept after claim");
        (, raw) = address(h).staticcall(abi.encodeWithSignature("getSwap(bytes32)", keccak256("none")));
        w = abi.decode(raw, (bytes32[7]));
        for (uint256 i = 0; i < 7; i++) eq(w[i], bytes32(0), "absent id is all zero");
    }

    /// Signature strings hard-coded in swapnet/evm_driver.py and swapnet/evm.py.
    function test_driverSelectorsAndTopicsMatch() public view {
        eq(bytes32(bytes4(keccak256("lockNative(bytes32,bytes32,address,uint64)"))), bytes32(SwapNetHTLC.lockNative.selector), "lockNative");
        eq(bytes32(bytes4(keccak256("lockToken(bytes32,bytes32,address,uint64,address,uint256)"))), bytes32(SwapNetHTLC.lockToken.selector), "lockToken");
        eq(bytes32(bytes4(keccak256("claim(bytes32,bytes32)"))), bytes32(SwapNetHTLC.claim.selector), "claim");
        eq(bytes32(bytes4(keccak256("refund(bytes32)"))), bytes32(SwapNetHTLC.refund.selector), "refund");
        eq(bytes32(bytes4(keccak256("withdrawAmount(address,address,uint256)"))), bytes32(SwapNetHTLC.withdrawAmount.selector), "withdrawAmount");
        eq(bytes32(bytes4(keccak256("credits(address,address)"))), bytes32(h.credits.selector), "credits");
        eq(bytes32(bytes4(keccak256("getSwap(bytes32)"))), bytes32(SwapNetHTLC.getSwap.selector), "getSwap");
        eq(keccak256("Locked(bytes32,bytes32,address,address,address,uint256,uint64)"), SwapNetHTLC.Locked.selector, "Locked topic");
        eq(keccak256("Claimed(bytes32,bytes32)"), SwapNetHTLC.Claimed.selector, "Claimed topic");
    }

    function test_reentrancyFlagClearAfterEveryEntryPoint() public {
        (bytes32 id, uint64 refundAt) = lockDefault();
        eq(vm.load(address(h), bytes32(uint256(2))), bytes32(0), "after lock");
        bytes32 id2 = lockAs(FUNDER, bytes32(uint256(8)), HL, CLAIMANT, refundAt, 1 ether);
        h.claim(id, SECRET);
        eq(vm.load(address(h), bytes32(uint256(2))), bytes32(0), "after claim");
        vm.warp(refundAt); h.refund(id2);
        eq(vm.load(address(h), bytes32(uint256(2))), bytes32(0), "after refund");
        vm.prank(CLAIMANT); h.withdrawTo(address(0), payable(CLAIMANT));
        eq(vm.load(address(h), bytes32(uint256(2))), bytes32(0), "after withdraw");
    }
}
