// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../SwapNetHTLC.sol";
import "./utils/Base.sol";
import "./utils/Tokens.sol";
import "./utils/Actors.sol";

/// ERC-20 path. The off-chain runtime enables native ETH only today, but lockToken is public,
/// so its accept/reject behaviour is part of the deployed contract's surface.
contract SwapNetHTLCTokensTest is Base {
    SwapNetHTLC h;
    address constant FUNDER = address(0xF0D0);
    address constant CLAIMANT = address(0xC1A1);
    bytes32 constant SECRET = bytes32(uint256(42));
    bytes32 constant SALT = bytes32(uint256(1));
    bytes32 HL;

    function setUp() public {
        vm.warp(1_800_000_000);
        h = new SwapNetHTLC();
        HL = sha256(abi.encodePacked(SECRET));
    }

    function lockT(address token, uint256 amount) internal returns (bytes32 id, uint64 refundAt) {
        refundAt = uint64(block.timestamp + 4 hours);
        vm.prank(FUNDER);
        id = h.lockToken(SALT, HL, CLAIMANT, refundAt, token, amount);
    }

    function funded(StdToken t, uint256 amount) internal {
        t.mint(FUNDER, amount);
        vm.prank(FUNDER);
        t.approve(address(h), type(uint256).max);
    }

    function state(bytes32 id) internal view returns (SwapNetHTLC.State st) { (,,,,,, st) = h.getSwap(id); }

    // ---------- standard token ----------
    function test_std_lockClaimWithdraw() public {
        StdToken t = new StdToken(); funded(t, 100);
        (bytes32 id,) = lockT(address(t), 60);
        eq(t.balanceOf(address(h)), 60, "pulled");
        (, address tok,,, uint256 amt,,) = h.getSwap(id);
        eq(tok, address(t), "token recorded"); eq(amt, 60, "amount");
        h.claim(id, SECRET);
        eq(h.credits(CLAIMANT, address(t)), 60, "token credit");
        eq(h.credits(CLAIMANT, address(0)), 0, "separate from ETH credit");
        vm.prank(CLAIMANT); h.withdrawAmount(address(t), payable(CLAIMANT), 60);
        eq(t.balanceOf(CLAIMANT), 60, "paid"); eq(t.balanceOf(address(h)), 0, "drained");
    }

    function test_std_refundPath() public {
        StdToken t = new StdToken(); funded(t, 100);
        (bytes32 id, uint64 refundAt) = lockT(address(t), 100);
        vm.warp(refundAt); h.refund(id);
        vm.prank(FUNDER); h.withdrawTo(address(t), payable(FUNDER));
        eq(t.balanceOf(FUNDER), 100, "refunded");
    }

    function test_rejectsZeroEoaPrecompileAndSelfAsToken() public {
        vm.startPrank(FUNDER);
        vm.expectRevert(SwapNetHTLC.UnsupportedToken.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(0), 1);
        vm.expectRevert(SwapNetHTLC.UnsupportedToken.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(0x1234), 1);
        vm.expectRevert(SwapNetHTLC.UnsupportedToken.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(2), 1); // sha256 precompile
        vm.expectRevert(SwapNetHTLC.UnsupportedToken.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(h), 1);
        vm.stopPrank();
    }

    function test_invalidTermsCheckedBeforeTokenCall() public {
        StdToken t = new StdToken(); funded(t, 10);
        vm.prank(FUNDER);
        vm.expectRevert(SwapNetHTLC.InvalidTerms.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(t), 0);
    }

    function test_missingAllowanceFails() public {
        StdToken t = new StdToken(); t.mint(FUNDER, 10);
        vm.prank(FUNDER);
        vm.expectRevert(SwapNetHTLC.TransferFailed.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(t), 10);
        eq(uint256(state(h.computeId(FUNDER, SALT))), 0, "nothing recorded");
    }

    // ---------- non-standard return values ----------
    function test_noReturnTokenAccepted() public {
        NoReturnToken t = new NoReturnToken(); funded(t, 50);
        (bytes32 id,) = lockT(address(t), 50);
        h.claim(id, SECRET);
        vm.prank(CLAIMANT); h.withdrawTo(address(t), payable(CLAIMANT));
        eq(t.balanceOf(CLAIMANT), 50, "USDT-style token works end to end");
    }

    function test_falseReturnRejectedBothWays() public {
        FalseReturnToken t = new FalseReturnToken(); funded(t, 50);
        t.setFail(false, true);
        vm.prank(FUNDER);
        vm.expectRevert(SwapNetHTLC.TransferFailed.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(t), 50);
        t.setFail(false, false);
        (bytes32 id,) = lockT(address(t), 50);
        h.claim(id, SECRET);
        t.setFail(true, false);
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.TransferFailed.selector);
        h.withdrawTo(address(t), payable(CLAIMANT));
        eq(h.credits(CLAIMANT, address(t)), 50, "credit kept");
    }

    function test_nonCanonicalBoolReturnRejected() public {
        NonBoolToken t = new NonBoolToken(); funded(t, 5);
        (bytes32 id,) = lockT(address(t), 5);
        h.claim(id, SECRET);
        vm.prank(CLAIMANT);
        vm.expectRevert(); // abi.decode(bool) rejects the word 2
        h.withdrawTo(address(t), payable(CLAIMANT));
        eq(h.credits(CLAIMANT, address(t)), 5, "credit kept");
    }

    function test_badBalanceOfRejected() public {
        for (uint256 m = 1; m <= 3; m++) {
            BadBalanceToken t = new BadBalanceToken(); t.mint(FUNDER, 10); t.setMode(m);
            vm.prank(FUNDER);
            vm.expectRevert(SwapNetHTLC.UnsupportedToken.selector);
            h.lockToken(bytes32(m), HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(t), 10);
        }
    }

    // ---------- transfer tax ----------
    function test_feeOnTransferRejectedAtLock() public {
        FeeToken t = new FeeToken(); funded(t, 1000); t.setFee(100);
        vm.prank(FUNDER);
        vm.expectRevert(SwapNetHTLC.UnsupportedToken.selector);
        h.lockToken(SALT, HL, CLAIMANT, uint64(block.timestamp + 2 hours), address(t), 1000);
    }

    /// A fee switched on after lock freezes withdrawal (exact-delta check) until it is switched off.
    /// No value is lost; the credit stays intact. Token admission must exclude fee switches.
    function test_feeSwitchAfterLockFreezesWithdrawalOnly() public {
        FeeToken t = new FeeToken(); funded(t, 1000);
        (bytes32 id,) = lockT(address(t), 1000);
        h.claim(id, SECRET);
        t.setFee(100);
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.UnsupportedToken.selector);
        h.withdrawTo(address(t), payable(CLAIMANT));
        eq(h.credits(CLAIMANT, address(t)), 1000, "credit intact while frozen");
        t.setFee(0);
        vm.prank(CLAIMANT); h.withdrawTo(address(t), payable(CLAIMANT));
        eq(t.balanceOf(CLAIMANT), 1000, "withdrawable again");
    }

    // ---------- rebasing ----------
    /// Documented residual (contract comment at withdrawTo): a negative rebase after lock makes the
    /// contract hold less than it owes, so the last credit cannot be withdrawn in full.
    function test_negativeRebaseLeavesLastCreditShort() public {
        ElasticToken t = new ElasticToken();
        t.mint(FUNDER, 200);
        vm.prank(FUNDER); t.approve(address(h), type(uint256).max);
        uint64 refundAt = uint64(block.timestamp + 4 hours);
        vm.startPrank(FUNDER);
        bytes32 id1 = h.lockToken(bytes32(uint256(1)), HL, CLAIMANT, refundAt, address(t), 100);
        bytes32 id2 = h.lockToken(bytes32(uint256(2)), HL, CLAIMANT, refundAt, address(t), 100);
        vm.stopPrank();
        h.claim(id1, SECRET); h.claim(id2, SECRET);
        t.rebase(0.5e18); // the contract now holds 100 but owes 200
        vm.prank(CLAIMANT); h.withdrawAmount(address(t), payable(CLAIMANT), 100);
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.TransferFailed.selector);
        h.withdrawAmount(address(t), payable(CLAIMANT), 100);
        eq(h.credits(CLAIMANT, address(t)), 100, "short credit stays recorded");
    }

    // ---------- issuer blocklist ----------
    function test_blockedClaimToCanWithdrawElsewhere() public {
        BlockToken t = new BlockToken(); funded(t, 10);
        (bytes32 id,) = lockT(address(t), 10);
        h.claim(id, SECRET);
        t.setBlocked(CLAIMANT, true);
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.TransferFailed.selector);
        h.withdrawTo(address(t), payable(CLAIMANT));
        vm.prank(CLAIMANT); h.withdrawTo(address(t), payable(address(0xD357)));
        eq(t.balanceOf(address(0xD357)), 10, "pull + free recipient avoids a blocklist freeze");
    }

    function test_blockedContractFreezesThatToken() public {
        BlockToken t = new BlockToken(); funded(t, 10);
        (bytes32 id,) = lockT(address(t), 10);
        h.claim(id, SECRET);
        t.setBlocked(address(h), true);
        vm.prank(CLAIMANT);
        vm.expectRevert(SwapNetHTLC.TransferFailed.selector);
        h.withdrawTo(address(t), payable(address(0xD357)));
        eq(h.credits(CLAIMANT, address(t)), 10, "issuer action freezes, nothing else can");
    }

    // ---------- hooks and reentrancy ----------
    function test_hookReentryBlockedDuringLockAndWithdraw() public {
        HookToken t = new HookToken(); funded(t, 100);
        TokenReentrancyProbe p = new TokenReentrancyProbe(h);
        t.setHook(address(p));
        // during lockToken's transferFrom
        p.arm(abi.encodeCall(SwapNetHTLC.refund, (h.computeId(FUNDER, SALT))));
        (bytes32 id,) = lockT(address(t), 50);
        ok(p.tried() && !p.succeeded(), "re-entry during lock blocked");
        eq(bytes32(p.ret()), bytes32(SwapNetHTLC.Reentrant.selector), "Reentrant");
        h.claim(id, SECRET); // hook not triggered by claim (no token call)
        // during withdraw's transfer
        p.arm(abi.encodeCall(SwapNetHTLC.withdrawAmount, (address(t), payable(CLAIMANT), 1)));
        vm.prank(CLAIMANT); h.withdrawAmount(address(t), payable(CLAIMANT), 10);
        ok(p.tried() && !p.succeeded(), "re-entry during withdraw blocked");
        eq(h.credits(CLAIMANT, address(t)), 40, "accounting exact");
    }
}
