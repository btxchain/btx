#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Deep-fork auto-resolve LOCAL POLICY twin-fork harness (RB-14 / deepforkautoresolve).

A default-on `-deepforkautoresolve` local policy auto-migrates this node to an
HONEST deep (> park_depth) strictly-heavier competing fork using NETWORK
OBSERVATION, while still refusing a dump-and-run. It is a local fork-choice
preference, never a consensus rule, and fails SAFE to today's PARK + RB-14 warn
when signals are ambiguous.

The decisive, unforgeable signal is VICTIM-RELATIVE HEIGHT at first-seen
(CBlockIndex::nActiveTipHeightAtFirstSeen): an honest live competing chain is
first seen block-by-block while this node's tip is near each block's height; any
post-hoc reveal (flash OR paced) is first seen while this node's tip is already
at the pre-attack height, far above the low suffix blocks. See
kernel::DeepForkAutoResolveBlockSeenLive.

Cases proven:
  (a) honest live-propagated deep reorg  -> AUTO-MIGRATE (tip follows the fork)
  (b) flash-revealed deep dump-and-run   -> REFUSED / PARKED (tip unchanged)
  (d) -deepforkautoresolve=0             -> PARK despite the honest shape

submitheader is refused on MatMul chains, so competing blocks are delivered with
submitblock (same AddToBlockIndex first-seen stamp as P2P HEADERS). The unit
backstop for the pure kernel predicates lives in
src/test/matmul_gpu_verified_transition_tests.cpp
(deep_fork_auto_resolve_predicates).
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PARK_DEPTH = 6
REORG_PROTECTION_START = 5
# A strictly-heavier COMPETING fork deeper than PARK_DEPTH triggers the policy.
FORK_HEIGHT = 10
DEEP_SUFFIX = PARK_DEPTH + 2  # 8 blocks; reorg_depth 8 > park_depth 6
EXTRA_WINNER = 1  # one extra block so the honest fork is strictly heavier


def common_args(extra=None):
    args = [
        "-parkdeepreorg=1",
        f"-maxreorgdepthpark={PARK_DEPTH}",
        f"-regtestreorgprotectionstartheight={REORG_PROTECTION_START}",
        "-reorghysteresisdepth=0",
        "-reorghysteresisworkmargin=0",
        "-cadenceburstmax=0",
        # First-seen must hold the equal-work loser so the competing suffix is
        # stamped while this node is still on the losing twin (default
        # -randomtiebreak=1 can switch at equal work).
        "-randomtiebreak=0",
        # test-sized deep-fork-auto-resolve windows
        "-deepforkautoresolvesustain=5",
        "-deepforkautoresolvefreshness=100000",
        "-deepforkautoresolveheightslack=2",
    ]
    if extra:
        args += extra
    return args


class DeepForkAutoResolveTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        # 0 = U_live (policy on)  — case (a)
        # 1 = A honest miner
        # 2 = U_dump (policy on)  — case (b)
        # 3 = U_off (policy off)  — case (d)
        self.extra_args = [
            common_args(),
            common_args(),
            common_args(),
            common_args(["-deepforkautoresolve=0"]),
        ]

    def setup_network(self):
        # Isolated nodes. submitheader is refused on MatMul, so every body —
        # common prefix and competing suffix — is delivered with submitblock
        # (same AddToBlockIndex first-seen stamp as P2P HEADERS). Avoids the
        # default 0-1-2-3 P2P chain, which is not under test here.
        self.setup_nodes()

    def parked_roots(self, node):
        info = node.getdifficultyhealth(5).get("reorg_protection", {})
        return info.get("parked_branch_roots", [])

    def submit_block(self, src, dest, blockhash):
        raw = src.getblock(blockhash, False)
        result = dest.submitblock(raw)
        assert result in (None, "duplicate", "inconclusive"), (
            f"submitblock({blockhash}) -> {result}"
        )

    def ancestor_hashes(self, node, stop_height):
        """Hashes from tip down to (but not including) stop_height, oldest first."""
        hashes = []
        blockhash = node.getbestblockhash()
        while True:
            header = node.getblockheader(blockhash)
            if header["height"] <= stop_height:
                break
            hashes.append(blockhash)
            blockhash = header["previousblockhash"]
        hashes.reverse()
        return hashes

    def push_chain(self, src, dest, stop_height):
        for blockhash in self.ancestor_hashes(src, stop_height):
            self.submit_block(src, dest, blockhash)

    def run_test(self):
        u_live, a, u_dump, u_off = self.nodes

        # Phase 0: common chain to the fork point; all four agree.
        self.generate(a, FORK_HEIGHT, sync_fun=self.no_op)
        for dest in (u_live, u_dump, u_off):
            self.push_chain(a, dest, stop_height=0)
            assert_equal(dest.getbestblockhash(), a.getbestblockhash())
        assert_equal(u_live.getblockcount(), FORK_HEIGHT)
        common_tip = u_live.getbestblockhash()

        # -------- Case (a): honest live-propagated deep reorg -> MIGRATE ------
        # U mines the losing child first; A mines the winning twin; the winning
        # body is submitted while U's tip is still at that height so
        # nActiveTipHeightAtFirstSeen ~= nHeight. Equal work holds the loser.
        # Then A mines one extra block (strictly heavier, depth > park) and
        # that extra is also first-seen near tip. Sustain span is the sleeps.
        self.log.info("Case (a): honest live-propagated deep reorg auto-migrates")
        for i in range(DEEP_SUFFIX):
            self.generate(u_live, 1, sync_fun=self.no_op)
            self.generate(a, 1, sync_fun=self.no_op)
            self.submit_block(a, u_live, a.getbestblockhash())
            assert_equal(u_live.getblockcount(), FORK_HEIGHT + i + 1)
            assert u_live.getbestblockhash() != a.getbestblockhash(), (
                "equal-work winning twin must not reorg the first-seen loser"
            )
            time.sleep(1)
        self.generate(a, EXTRA_WINNER, sync_fun=self.no_op)
        self.submit_block(a, u_live, a.getbestblockhash())
        self.wait_until(
            lambda: u_live.getbestblockhash() == a.getbestblockhash(),
            timeout=120,
        )
        assert_equal(u_live.getblockcount(), FORK_HEIGHT + DEEP_SUFFIX + EXTRA_WINNER)
        self.log.info("Case (a) passed: U_live followed the honest heavier fork")

        # -------- Case (b): flash-revealed dump-and-run -> PARK --------------
        # U_dump mines DEEP_SUFFIX on the common parent in isolation, then
        # receives A's already-complete heavier suffix in one shot. Every low
        # suffix block is first-seen while U_dump's tip is already at
        # FORK+DEEP_SUFFIX >> block height → seen_live fails → park.
        self.log.info("Case (b): flash dump-and-run parks")
        assert_equal(u_dump.getbestblockhash(), common_tip)
        self.generate(u_dump, DEEP_SUFFIX, sync_fun=self.no_op)
        dump_tip = u_dump.getbestblockhash()
        assert_equal(u_dump.getblockcount(), FORK_HEIGHT + DEEP_SUFFIX)
        for blockhash in self.ancestor_hashes(a, FORK_HEIGHT):
            self.submit_block(a, u_dump, blockhash)
        assert_equal(u_dump.getbestblockhash(), dump_tip)
        assert u_dump.getbestblockhash() != a.getbestblockhash(), (
            "flash dump-and-run must NOT be auto-followed"
        )
        assert self.parked_roots(u_dump), "heavier dump fork must be parked"
        self.log.info("Case (b) passed: flash dump stayed parked")

        # -------- Case (d): -deepforkautoresolve=0 -> PARK -------------------
        # Same honest-live first-seen shape as (a), but this node started with
        # the policy off, so in_scope is false and the heavier fork parks.
        self.log.info("Case (d): -deepforkautoresolve=0 parks the honest shape")
        assert_equal(u_off.getbestblockhash(), common_tip)
        for i in range(DEEP_SUFFIX):
            self.generate(u_off, 1, sync_fun=self.no_op)
            self.submit_block(a, u_off, a.getblockhash(FORK_HEIGHT + i + 1))
            time.sleep(1)
        off_loser = u_off.getbestblockhash()
        self.submit_block(a, u_off, a.getbestblockhash())
        time.sleep(2)
        assert_equal(u_off.getbestblockhash(), off_loser)
        assert u_off.getbestblockhash() != a.getbestblockhash(), (
            "-deepforkautoresolve=0 must not auto-follow the honest heavier fork"
        )
        assert self.parked_roots(u_off), (
            "-deepforkautoresolve=0 must park the heavier fork"
        )
        self.log.info("Case (d) passed: disabled policy parked")


if __name__ == "__main__":
    DeepForkAutoResolveTest(__file__).main()
