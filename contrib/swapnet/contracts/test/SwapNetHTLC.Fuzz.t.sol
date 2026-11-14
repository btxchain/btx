// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../SwapNetHTLC.sol";
import "./utils/Base.sol";

/// Stateless properties, fuzzed over terms, times, preimages and callers.
contract SwapNetHTLCFuzzTest is Base {
    SwapNetHTLC h;
    address constant FUNDER = address(0xF0D0);
    address constant CLAIMANT = address(0xC1A1);
    uint256 constant T0 = 1_800_000_000;

    function setUp() public {
        vm.warp(T0);
        h = new SwapNetHTLC();
        vm.deal(FUNDER, type(uint128).max);
    }

    function lock(bytes32 salt, bytes32 preimage, uint256 amount, uint64 refundAt) internal returns (bytes32 id) {
        bytes32 hl = sha256(abi.encodePacked(preimage));
        vm.prank(FUNDER);
        id = h.lockNative{value: amount}(salt, hl, CLAIMANT, refundAt);
    }

    /// Lock window: accepted iff now + MIN_LOCK <= refundAt <= now + MAX_LOCK.
    function testFuzz_lockWindow(uint256 rawRefundAt, uint256 now_) public {
        now_ = bound(now_, 2 days, type(uint64).max - 33 days);
        // Concentrate refundAt around the window so both sides and both edges are exercised.
        uint64 refundAt = uint64(bound(rawRefundAt, now_ - 2 days, now_ + 32 days));
        vm.warp(now_);
        bytes32 hl = sha256(abi.encodePacked(bytes32(uint256(1))));
        vm.prank(FUNDER);
        (bool s,) = address(h).call{value: 1}(abi.encodeCall(SwapNetHTLC.lockNative, (bytes32(0), hl, CLAIMANT, refundAt)));
        bool inWindow = uint256(refundAt) >= now_ + 1 hours && uint256(refundAt) <= now_ + 30 days;
        ok(s == inWindow, "lock accepted exactly inside the window");
    }

    /// Any terms that break one InvalidTerms rule are rejected and leave no state.
    function testFuzz_invalidTermsLeaveNoState(uint8 which, bytes32 salt, uint256 amount) public {
        which = uint8(bound(which, 0, 4));
        amount = bound(amount, 1, 1e30);
        bytes32 hl = bytes32(uint256(5));
        address claimTo = CLAIMANT;
        uint64 refundAt = uint64(block.timestamp + 2 hours);
        if (which == 0) hl = bytes32(0);
        if (which == 1) claimTo = address(0);
        if (which == 2) claimTo = address(h);
        if (which == 3) claimTo = FUNDER;
        if (which == 4) amount = 0;
        bytes32 id = h.computeId(FUNDER, salt);
        vm.prank(FUNDER);
        (bool s, bytes memory r) = address(h).call{value: amount}(abi.encodeCall(SwapNetHTLC.lockNative, (salt, hl, claimTo, refundAt)));
        ok(!s, "rejected");
        eq(bytes32(r), bytes32(SwapNetHTLC.InvalidTerms.selector), "InvalidTerms");
        (,,,,,, SwapNetHTLC.State st) = h.getSwap(id);
        ok(st == SwapNetHTLC.State.Absent, "no state");
        eq(address(h).balance, 0, "no value kept");
    }

    /// At any time t exactly one of claim (t < refundAt) or refund (t >= refundAt) succeeds.
    function testFuzz_claimRefundPartitionTime(uint256 dur, uint256 dt, bytes32 preimage) public {
        dur = bound(dur, 1 hours, 30 days);
        uint64 refundAt = uint64(block.timestamp + dur);
        bytes32 id = lock(bytes32(0), preimage, 1 ether, refundAt);
        dt = bound(dt, 0, dur + 365 days);
        vm.warp(T0 + dt);
        uint256 snap = vm.snapshotState();
        (bool c,) = address(h).call(abi.encodeCall(SwapNetHTLC.claim, (id, preimage)));
        vm.revertToState(snap);
        (bool r,) = address(h).call(abi.encodeCall(SwapNetHTLC.refund, (id)));
        ok(c != r, "exactly one");
        ok(c == (block.timestamp < refundAt), "claim iff before refundAt");
    }

    /// A different preimage never claims.
    function testFuzz_wrongPreimageNeverClaims(bytes32 p, bytes32 q) public {
        vm.assume(p != q);
        bytes32 id = lock(bytes32(0), p, 1 ether, uint64(block.timestamp + 2 hours));
        vm.expectRevert(SwapNetHTLC.InvalidPreimage.selector);
        h.claim(id, q);
    }

    /// Whoever relays a claim or refund, the credit lands on the fixed beneficiary.
    function testFuzz_relayerCannotRedirect(address relayer, bytes32 preimage, bool doRefund) public {
        vm.assume(relayer != CLAIMANT && relayer != FUNDER && relayer != address(vm));
        uint64 refundAt = uint64(block.timestamp + 2 hours);
        bytes32 id = lock(bytes32(0), preimage, 3 ether, refundAt);
        if (doRefund) { vm.warp(refundAt); vm.prank(relayer); h.refund(id); }
        else { vm.prank(relayer); h.claim(id, preimage); }
        eq(h.credits(relayer, address(0)), 0, "relayer gets nothing");
        eq(h.credits(doRefund ? FUNDER : CLAIMANT, address(0)), 3 ether, "fixed beneficiary");
        eq(h.credits(doRefund ? CLAIMANT : FUNDER, address(0)), 0, "other party nothing");
    }

    /// Distinct (chain, funder, salt) give distinct ids, and the id equals the driver's encoding.
    function testFuzz_idBinding(uint64 chainA, uint64 chainB, address fA, address fB, bytes32 sA, bytes32 sB) public {
        vm.assume(chainA != 0 && chainB != 0);
        vm.chainId(chainA);
        bytes32 a = h.computeId(fA, sA);
        eq(a, keccak256(abi.encodePacked(uint256(chainA), uint256(uint160(address(h))), uint256(uint160(fA)), sA)), "driver encoding");
        vm.chainId(chainB);
        bytes32 b = h.computeId(fB, sB);
        ok((a == b) == (chainA == chainB && fA == fB && sA == sB), "injective on inputs");
    }

    /// Exact withdrawals in two parts pay precisely the credit, never more.
    function testFuzz_withdrawSplit(uint96 amount, uint96 part, address payable to) public {
        vm.assume(amount > 0 && to != address(0) && to != address(h) && uint160(address(to)) > 0xffff && to.code.length == 0);
        vm.assume(to != address(vm) && to != FUNDER);
        uint256 before = to.balance;
        bytes32 preimage = bytes32(uint256(amount));
        bytes32 id = lock(bytes32(0), preimage, amount, uint64(block.timestamp + 2 hours));
        h.claim(id, preimage);
        uint256 p = bound(part, 1, amount);
        vm.prank(CLAIMANT); h.withdrawAmount(address(0), to, p);
        if (p < amount) { vm.prank(CLAIMANT); h.withdrawAmount(address(0), to, amount - p); }
        eq(to.balance - before, amount, "paid exactly");
        eq(h.credits(CLAIMANT, address(0)), 0, "cleared");
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawAmount(address(0), to, 1);
    }

    /// Terms recorded at lock never change across claim or refund.
    function testFuzz_termsImmutable(bytes32 salt, bytes32 preimage, uint96 amount, uint256 dur, bool doRefund) public {
        vm.assume(amount > 0);
        dur = bound(dur, 1 hours, 30 days);
        uint64 refundAt = uint64(block.timestamp + dur);
        bytes32 id = lock(salt, preimage, amount, refundAt);
        bytes memory before = _terms(id);
        if (doRefund) { vm.warp(refundAt); h.refund(id); } else { h.claim(id, preimage); }
        eq(keccak256(_terms(id)), keccak256(before), "terms immutable");
        (,,,,,, SwapNetHTLC.State st) = h.getSwap(id);
        ok(st == (doRefund ? SwapNetHTLC.State.Refunded : SwapNetHTLC.State.Claimed), "terminal state");
    }

    function _terms(bytes32 id) internal view returns (bytes memory t) {
        (, bytes memory raw) = address(h).staticcall(abi.encodeCall(SwapNetHTLC.getSwap, (id)));
        t = new bytes(192);
        for (uint256 i = 0; i < 192; i++) t[i] = raw[i];
    }
}
