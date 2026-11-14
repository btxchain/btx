// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../SwapNetHTLC.sol";
import "./utils/Base.sol";
import "./utils/Tokens.sol";
import "./utils/Actors.sol";

/// Drives random sequences of lock / claim / refund / withdraw / time jumps across several actors
/// and one standard token, and keeps a ghost model of what the contract must hold and owe.
contract HTLCHandler is Base {
    SwapNetHTLC public immutable h;
    StdToken public immutable tok;
    address[4] public actors = [address(0xA1), address(0xA2), address(0xA3), address(0xA4)];

    struct Rec {
        bytes32 id; bytes32 hashlock; bytes32 preimage; address token; address refundTo; address claimTo;
        uint256 amount; uint64 refundAt; uint8 state; // 1 Locked, 2 Claimed, 3 Refunded
    }
    Rec[] public recs;
    uint256 public saltNonce;

    // ghost totals
    uint256 public lockedEth; uint256 public lockedTok; uint256 public forcedEth;
    mapping(address => mapping(address => uint256)) public ghostCredit;
    // violation flags (must stay false)
    bool public lateClaim; bool public earlyRefund; bool public wrongPreimageClaimed;
    bool public validClaimRejected; bool public validRefundRejected; bool public overWithdraw;
    bool public reentryFlagDirty; bool public idReused; bool public doubleSettle;
    uint256 public calls;

    constructor(SwapNetHTLC h_, StdToken t_) {
        h = h_; tok = t_;
        for (uint256 i = 0; i < 4; i++) {
            vm.deal(actors[i], 1e30);
            t_.mint(actors[i], 1e30);
            vm.prank(actors[i]); t_.approve(address(h_), type(uint256).max);
        }
    }

    function recCount() external view returns (uint256) { return recs.length; }
    function rec(uint256 i) external view returns (Rec memory) { return recs[i]; }

    function _actor(uint256 s) internal view returns (address) { return actors[s % 4]; }
    function _checkFlag() internal { if (vm.load(address(h), bytes32(uint256(2))) != bytes32(0)) reentryFlagDirty = true; calls++; }

    function lock(uint256 fSeed, uint256 cSeed, uint256 amount, uint256 dur, bytes32 preimage, bool useToken) external {
        Rec memory r;
        r.refundTo = _actor(fSeed); r.claimTo = _actor(cSeed);
        if (r.claimTo == r.refundTo) r.claimTo = _actor(cSeed % 4 + 1);
        r.amount = bound(amount, 1, 1e24);
        r.refundAt = uint64(block.timestamp + bound(dur, 1 hours, 30 days));
        r.preimage = preimage;
        r.hashlock = sha256(abi.encodePacked(preimage));
        if (r.hashlock == bytes32(0)) return;
        r.token = useToken ? address(tok) : address(0);
        r.state = 1;
        _lock(r, bytes32(++saltNonce));
    }

    function _lock(Rec memory r, bytes32 salt) internal {
        r.id = h.computeId(r.refundTo, salt);
        vm.prank(r.refundTo);
        if (r.token != address(0)) h.lockToken(salt, r.hashlock, r.claimTo, r.refundAt, r.token, r.amount);
        else h.lockNative{value: r.amount}(salt, r.hashlock, r.claimTo, r.refundAt);
        recs.push(r);
        if (r.token != address(0)) lockedTok += r.amount; else lockedEth += r.amount;
        _checkFlag();
    }

    function relockSameSalt(uint256 i, uint256 amount) external {
        if (recs.length == 0) return;
        Rec memory r = recs[i % recs.length];
        amount = bound(amount, 1, 1e24);
        // recover the salt: ids are sender-scoped; reuse is detected by AlreadyExists
        for (uint256 s = 1; s <= saltNonce; s++) {
            if (h.computeId(r.refundTo, bytes32(s)) == r.id) {
                vm.prank(r.refundTo);
                try h.lockNative{value: amount}(bytes32(s), r.hashlock, r.claimTo, uint64(block.timestamp + 2 hours)) {
                    idReused = true; // an id must never be locked twice
                } catch {}
                break;
            }
        }
        _checkFlag();
    }

    function claim(uint256 i, uint256 relayer, bool wrong) external {
        if (recs.length == 0) return;
        Rec storage r = recs[i % recs.length];
        bytes32 p = wrong ? keccak256(abi.encode(r.preimage)) : r.preimage;
        bool shouldWork = r.state == 1 && block.timestamp < r.refundAt && !wrong;
        vm.prank(_actor(relayer));
        try h.claim(r.id, p) {
            if (block.timestamp >= r.refundAt) lateClaim = true;
            if (wrong) wrongPreimageClaimed = true;
            if (r.state != 1) doubleSettle = true;
            if (r.state == 1) {
                r.state = 2;
                if (r.token == address(0)) lockedEth -= r.amount; else lockedTok -= r.amount;
                ghostCredit[r.claimTo][r.token] += r.amount;
            }
        } catch {
            if (shouldWork) validClaimRejected = true;
        }
        _checkFlag();
    }

    function refund(uint256 i, uint256 relayer) external {
        if (recs.length == 0) return;
        Rec storage r = recs[i % recs.length];
        bool shouldWork = r.state == 1 && block.timestamp >= r.refundAt;
        vm.prank(_actor(relayer));
        try h.refund(r.id) {
            if (block.timestamp < r.refundAt) earlyRefund = true;
            if (r.state != 1) doubleSettle = true;
            if (r.state == 1) {
                r.state = 3;
                if (r.token == address(0)) lockedEth -= r.amount; else lockedTok -= r.amount;
                ghostCredit[r.refundTo][r.token] += r.amount;
            }
        } catch {
            if (shouldWork) validRefundRejected = true;
        }
        _checkFlag();
    }

    function withdraw(uint256 who, uint256 toSeed, uint256 amount, bool useToken, bool all) external {
        address owner = _actor(who);
        address token = useToken ? address(tok) : address(0);
        uint256 credit = ghostCredit[owner][token];
        address payable to = payable(address(uint160(0xD000 + (toSeed % 8))));
        uint256 amt = all ? credit : bound(amount, 0, credit + 2);
        vm.prank(owner);
        try h.withdrawAmount(token, to, amt) {
            if (amt == 0 || amt > credit) overWithdraw = true;
            // set the flag without underflowing, so a bad withdrawal is recorded rather than rolled back
            ghostCredit[owner][token] = amt > credit ? 0 : credit - amt;
        } catch {}
        _checkFlag();
    }

    function warp(uint256 dt) external {
        dt = bound(dt, 0, 31 days);
        vm.warp(block.timestamp + dt);
        _checkFlag();
    }

    function force(uint256 amount) external {
        amount = bound(amount, 1, 1e20);
        // ETH arriving without a call (selfdestruct beneficiary, block reward)
        vm.deal(address(h), address(h).balance + amount);
        forcedEth += amount;
        _checkFlag();
    }

    // ---------- end-of-run drain, used by afterInvariant ----------
    function drainAll() external {
        vm.warp(block.timestamp + 31 days);
        for (uint256 i = 0; i < recs.length; i++) {
            Rec storage r = recs[i];
            if (r.state == 1) {
                h.refund(r.id); r.state = 3;
                if (r.token == address(0)) lockedEth -= r.amount; else lockedTok -= r.amount;
                ghostCredit[r.refundTo][r.token] += r.amount;
            }
        }
        for (uint256 a = 0; a < 4; a++) {
            for (uint256 k = 0; k < 2; k++) {
                address token = k == 0 ? address(0) : address(tok);
                uint256 c = h.credits(actors[a], token);
                if (c > 0) {
                    vm.prank(actors[a]); h.withdrawTo(token, payable(address(0xD0FF)));
                    ghostCredit[actors[a]][token] = 0;
                }
            }
        }
    }
}

/// Stateful invariants over HTLCHandler.
contract SwapNetHTLCInvariantTest is Base {
    SwapNetHTLC h;
    StdToken tok;
    HTLCHandler hd;

    struct FuzzSelector { address addr; bytes4[] selectors; }

    function setUp() public {
        vm.warp(1_800_000_000);
        h = new SwapNetHTLC();
        tok = new StdToken();
        hd = new HTLCHandler(h, tok);
    }

    function targetContracts() public view returns (address[] memory a) { a = new address[](1); a[0] = address(hd); }

    function targetSelectors() public view returns (FuzzSelector[] memory s) {
        bytes4[] memory sel = new bytes4[](7);
        sel[0] = HTLCHandler.lock.selector; sel[1] = HTLCHandler.claim.selector; sel[2] = HTLCHandler.refund.selector;
        sel[3] = HTLCHandler.withdraw.selector; sel[4] = HTLCHandler.warp.selector; sel[5] = HTLCHandler.force.selector;
        sel[6] = HTLCHandler.relockSameSalt.selector;
        s = new FuzzSelector[](1); s[0] = FuzzSelector(address(hd), sel);
    }

    function _sumCredits(address token) internal view returns (uint256 sum) {
        for (uint256 i = 0; i < 4; i++) sum += h.credits(hd.actors(i), token);
    }

    /// I-SOLV-ETH: ETH held == ETH locked + ETH owed + ETH forced in (no leak, no shortfall).
    function invariant_ethSolvency() public view {
        eq(address(h).balance, hd.lockedEth() + _sumCredits(address(0)) + hd.forcedEth(), "ETH solvency");
    }

    /// I-SOLV-TOK: token held == token locked + token owed.
    function invariant_tokenSolvency() public view {
        eq(tok.balanceOf(address(h)), hd.lockedTok() + _sumCredits(address(tok)), "token solvency");
    }

    /// I-CREDIT: contract credits equal the ghost ledger for every actor and asset.
    function invariant_creditsMatchModel() public view {
        for (uint256 i = 0; i < 4; i++) {
            address a = hd.actors(i);
            eq(h.credits(a, address(0)), hd.ghostCredit(a, address(0)), "ETH credit model");
            eq(h.credits(a, address(tok)), hd.ghostCredit(a, address(tok)), "token credit model");
        }
    }

    /// I-STATE + I-IMMUTABLE: every recorded swap's on-chain state and terms equal the model.
    function invariant_stateAndTermsMatchModel() public view {
        uint256 n = hd.recCount();
        for (uint256 i = 0; i < n; i++) {
            HTLCHandler.Rec memory r = hd.rec(i);
            (bytes32 hl, address token, address refundTo, address claimTo, uint256 amount, uint64 refundAt, SwapNetHTLC.State st) = h.getSwap(r.id);
            ok(hl == r.hashlock && token == r.token && refundTo == r.refundTo && claimTo == r.claimTo &&
               amount == r.amount && refundAt == r.refundAt, "terms immutable");
            eq(uint256(st), uint256(r.state), "state matches model");
        }
    }

    /// I-WINDOW / I-PREIMAGE / I-LIVE / I-LOCK: no call ever succeeded outside its rules,
    /// no valid call was ever refused, and the reentrancy flag is clear between calls.
    function invariant_noRuleViolations() public view {
        ok(!hd.lateClaim(), "claim at/after refundAt");
        ok(!hd.earlyRefund(), "refund before refundAt");
        ok(!hd.wrongPreimageClaimed(), "claim with wrong preimage");
        ok(!hd.validClaimRejected(), "valid claim refused");
        ok(!hd.idReused(), "id locked twice");
        ok(!hd.doubleSettle(), "second claim or refund succeeded");
        ok(!hd.validRefundRejected(), "valid refund refused");
        ok(!hd.overWithdraw(), "withdrawal beyond credit");
        ok(!hd.reentryFlagDirty(), "reentrancy flag left set");
    }

    /// I-NOSTUCK: after every run, all locks can be refunded and all credits withdrawn,
    /// leaving only forced-in ETH and no tokens.
    function afterInvariant() public {
        hd.drainAll();
        eq(address(h).balance, hd.forcedEth(), "only forced ETH remains");
        eq(tok.balanceOf(address(h)), 0, "no tokens remain");
        eq(hd.lockedEth() + hd.lockedTok(), 0, "nothing locked");
    }
}
