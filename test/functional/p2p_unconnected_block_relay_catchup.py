#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Catch-up relay must not push a block before it is connected.

Besides the high-bandwidth path (p2p_unconnected_block_relay.py), NewPoWValidBlock
has a catch-up branch for a peer that is not a high-bandwidth compact peer. It
walks to the next block the peer is missing; when that block is the one just
validated (next == pindex), the old code pushed its full BLOCK even though the
block was not connected yet. A tip child that then failed ConnectBlock got the
honest relay disconnected.

Here the producer is node2, so high-bandwidth selection points 2 -> 1 -> 0 while
the bad block travels 0 -> 1 -> 2 as a plain block, which takes the catch-up
branch. The fix defers the body until the block connects, so the honest relays
are not disconnected.

Regtest only, loopback only.
"""

import time

from test_framework.blocktools import (
    REGTEST_GENERIC_P2P_MATMUL_ARGS,
    create_block,
    create_coinbase,
)
from test_framework.messages import COIN, msg_block
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class UnconnectedBlockRelayCatchupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            *REGTEST_GENERIC_P2P_MATMUL_ARGS,  # payload flag off by default
            "-debug=net",
            "-nomodelnet",
            "-modellandiscovery=0",
        ]
        self.extra_args = [common] * self.num_nodes

    def setup_network(self):
        self.setup_nodes()  # no automatic connections

    def outbound(self, a, b):
        self.nodes[a].addconnection(
            f"127.0.0.1:{p2p_port(b)}", "outbound-full-relay", False)
        self.wait_until(lambda: any(
            p["connection_type"] == "outbound-full-relay"
            for p in self.nodes[a].getpeerinfo()), timeout=15)

    def outbound_count(self, i):
        return sum(1 for p in self.nodes[i].getpeerinfo()
                   if p["connection_type"] == "outbound-full-relay")

    def tip_status(self, i, block_hash):
        for t in self.nodes[i].getchaintips():
            if t["hash"] == block_hash:
                return t["status"]
        return "unseen"

    def log_has(self, i, needle):
        with open(self.nodes[i].debug_log_path, encoding="utf-8", errors="replace") as f:
            return any(needle in line for line in f)

    def run_test(self):
        n0, n1, n2 = self.nodes
        # node2 -> node1 -> node0; node2 mines, so high-bandwidth selection
        # points against the direction the bad block will travel.
        self.outbound(2, 1)
        self.outbound(1, 0)
        self.generate(n2, 20, sync_fun=self.no_op)
        self.wait_until(lambda: n0.getbestblockhash() == n2.getbestblockhash(), timeout=120)
        self.wait_until(lambda: n1.getbestblockhash() == n2.getbestblockhash(), timeout=120)
        time.sleep(2)

        self.log.info("An unconnected invalid tip child does not disconnect the honest relays")
        tip_hash = n0.getbestblockhash()
        tip = n0.getblock(tip_hash)
        cb = create_coinbase(tip["height"] + 1)
        cb.vout[0].nValue += 1000 * COIN
        cb.rehash()
        bad = create_block(int(tip_hash, 16), cb, tip["time"] + 1)
        bad.solve()

        m = n0.add_p2p_connection(P2PDataStore())
        m.send_message(msg_block(bad))
        self.wait_until(lambda: self.tip_status(0, bad.hash) == "invalid", timeout=20)
        time.sleep(5)

        assert_equal(self.outbound_count(1), 1)
        assert_equal(self.outbound_count(2), 1)
        assert self.tip_status(1, bad.hash) in ("headers-only", "unseen")
        assert self.tip_status(2, bad.hash) in ("headers-only", "unseen")
        # node0 must not have pushed the unconnected body to node1.
        assert not self.log_has(0, f"sending next honest body {bad.hash}")
        assert not self.log_has(1, f"ConnectBlock {bad.hash}")


if __name__ == "__main__":
    UnconnectedBlockRelayCatchupTest(__file__).main()
