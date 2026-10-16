#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Every distinct deep-reorg alarm reaches the RPC warnings and -alertnotify.

Chainstate::ActivateBestChainStep raises DEEP_REORG_DETECTED for every reorg
it warns about or parks. The "Deep reorg detected" entry in the "warnings"
arrays of getblockchaininfo, getnetworkinfo and getmininginfo must describe
the latest alarm, and each distinct alarm must run -alertnotify once. An
operator who looks after a parked deep reorg must not see an older, shallower,
warn-only event instead. An identical repeat is logged, but it neither
replaces the entry nor alerts again.

Event 1: a 2-block cross-fork reorg (warn depth 1, park depth 3): warn, follow.
Event 1 again, between the same two tips: same alarm text, no new alert.
Event 2: a 4-block cross-fork reorg: park, stay on the current tip.
"""

import os

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

WARN_DEPTH = 1
PARK_DEPTH = 3


class DeepReorgWarningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.alert_file = os.path.join(self.options.tmpdir, "alertnotify.txt")
        self.extra_args = [[
            "-regtestreorgprotectionstartheight=5",
            f"-maxreorgdepthwarn={WARN_DEPTH}",
            f"-maxreorgdepthpark={PARK_DEPTH}",
            "-parkdeepreorg=1",
            "-deepforkautoresolve=0",
            "-reorghysteresisdepth=0",
            "-reorghysteresisworkmargin=0",
            "-cadenceburstmax=0",
            f"-alertnotify=echo %s >> {self.alert_file}",
        ]]
        self.setup_nodes()

    def deep_reorg_warnings(self, node):
        """The "Deep reorg detected" entries, identical in every RPC that reports warnings."""
        found = []
        for rpc in (node.getblockchaininfo, node.getnetworkinfo, node.getmininginfo):
            warnings = rpc()["warnings"]
            if isinstance(warnings, str):
                warnings = warnings.split("\n") if warnings else []
            found.append([w for w in warnings if "Deep reorg detected" in w])
        assert_equal(found[0], found[1])
        assert_equal(found[0], found[2])
        return found[0]

    def alerts(self):
        if not os.path.exists(self.alert_file):
            return []
        with open(self.alert_file, encoding="utf8") as f:
            return [line for line in f.read().splitlines() if "Deep reorg detected" in line]

    def cross_fork(self, node, depth):
        """Fork depth+1 blocks below the tip, mine a depth-block competing
        branch, then reconsider the heavier original branch. Returns the
        original tip, the competing tip, the fork height and the first block
        of the original branch."""
        original = node.getbestblockhash()
        fork_height = node.getblockcount() - depth - 1
        first_original = node.getblockhash(fork_height + 1)
        node.invalidateblock(first_original)
        assert_equal(node.getblockcount(), fork_height)
        self.generatetoaddress(node, depth, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        competing = node.getbestblockhash()
        assert_equal(node.getblockcount(), fork_height + depth)
        node.reconsiderblock(first_original)
        return original, competing, fork_height, first_original

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 20, sync_fun=self.no_op)
        assert_equal(self.deep_reorg_warnings(node), [])

        self.log.info("Event 1: 2-block reorg, past the warn depth, within the park depth: warn and follow")
        original, competing, fork1, first_original = self.cross_fork(node, 2)
        assert_equal(node.getbestblockhash(), original)
        warnings = self.deep_reorg_warnings(node)
        assert_equal(len(warnings), 1)
        assert "reorganize 2 blocks" in warnings[0] and f"fork={fork1}," in warnings[0], warnings[0]
        assert "Following the most-work chain" in warnings[0], warnings[0]
        self.wait_until(lambda: len(self.alerts()) == 1, timeout=10)

        self.log.info("Event 1 again, between the same two tips: logged, but no new entry and no new alert")
        node.invalidateblock(first_original)
        assert_equal(node.getbestblockhash(), competing)
        with node.assert_debug_log(expected_msgs=["Deep reorg detected: a branch would reorganize 2 blocks"]):
            node.reconsiderblock(first_original)
        assert_equal(node.getbestblockhash(), original)
        assert_equal(self.deep_reorg_warnings(node), warnings)

        self.log.info("Event 2: 4-block reorg, past the park depth: park and stay")
        self.generate(node, 5, sync_fun=self.no_op)
        _, competing, fork2, _ = self.cross_fork(node, 4)
        assert_equal(node.getbestblockhash(), competing)
        warnings = self.deep_reorg_warnings(node)
        assert_equal(len(warnings), 1)
        self.log.info(f"warnings entry after event 2: {warnings[0]}")
        assert "reorganize 4 blocks" in warnings[0] and f"fork={fork2}," in warnings[0], warnings[0]
        assert "Parking the branch" in warnings[0], warnings[0]

        # One alert per distinct alarm: event 1 and event 2, not the repeat.
        self.wait_until(lambda: len(self.alerts()) >= 2, timeout=10)
        alerts = self.alerts()
        assert_equal(len(alerts), 2)
        assert "Parking the branch" in alerts[1], alerts[1]


if __name__ == '__main__':
    DeepReorgWarningTest(__file__).main()
