#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""NewPoWValidBlock must not relay a block before it is connected.

NewPoWValidBlock runs in AcceptBlock, before WriteBlock and ConnectTip. On the
high-bandwidth path for a product-payload block it used to push the full BLOCK
there. If that block then failed ConnectBlock, the receiving peer treated the
unsolicited full block as invalid data and disconnected the honest relay that
forwarded it. Product-payload blocks are consensus-required from a fixed height
on the main chain, so this path is reached in normal operation.

The fix defers the header and body until the block connects and sends them from
FlushDeferredFastBodies(). This test drives the high-bandwidth path (the block
producer mines, so its peers select it as their high-bandwidth peer) and checks
that:

  * a valid block still reaches the peers (the deferred body is delivered), and
  * an invalid tip child no longer disconnects the honest relays, and
  * with the payload flag off the unchanged compact-block path still does not
    punish anyone.

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


class UnconnectedBlockRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def node_args(self, payload):
        return [
            a for a in REGTEST_GENERIC_P2P_MATMUL_ARGS
            if not a.startswith("-regtestmatmulrequireproductpayload=")
        ] + [
            f"-regtestmatmulrequireproductpayload={payload}",
            "-debug=net",
            "-nomodelnet",
            "-modellandiscovery=0",
        ]

    def setup_network(self):
        # Start with the payload flag on; setup_nodes makes no connections.
        self.extra_args = [self.node_args(1)] * self.num_nodes
        self.setup_nodes()

    def outbound(self, a, b):
        self.nodes[a].addconnection(
            f"127.0.0.1:{p2p_port(b)}", "outbound-full-relay", False)
        self.wait_until(lambda: any(
            p["connection_type"] == "outbound-full-relay"
            for p in self.nodes[a].getpeerinfo()), timeout=15)

    def outbound_count(self, i):
        return sum(1 for p in self.nodes[i].getpeerinfo()
                   if p["connection_type"] == "outbound-full-relay")

    def hb_to(self, i):
        # Has this node selected its outbound peer as a high-bandwidth peer?
        return any(p["connection_type"] == "outbound-full-relay" and p["bip152_hb_to"]
                   for p in self.nodes[i].getpeerinfo())

    def tip_status(self, i, block_hash):
        for t in self.nodes[i].getchaintips():
            if t["hash"] == block_hash:
                return t["status"]
        return "unseen"

    def log_has(self, i, needle):
        with open(self.nodes[i].debug_log_path, encoding="utf-8", errors="replace") as f:
            return any(needle in line for line in f)

    def link_and_fill(self):
        # node2 -> node1 -> node0. node0 is the block producer, so node1 picks
        # node0 and node2 picks node1 as their high-bandwidth peer, which is
        # the direction the next block travels.
        self.outbound(2, 1)
        self.outbound(1, 0)
        n0 = self.nodes[0]
        for _ in range(12):
            self.generate(n0, 1, sync_fun=self.no_op)
            self.wait_until(lambda: self.nodes[1].getbestblockhash() == n0.getbestblockhash(), timeout=30)
            self.wait_until(lambda: self.nodes[2].getbestblockhash() == n0.getbestblockhash(), timeout=30)
        self.wait_until(lambda: self.hb_to(1) and self.hb_to(2), timeout=30)

    def bad_tip_child(self, node):
        tip_hash = node.getbestblockhash()
        tip = node.getblock(tip_hash)
        cb = create_coinbase(tip["height"] + 1)
        cb.vout[0].nValue += 1000 * COIN  # fails only in ConnectBlock
        cb.rehash()
        bad = create_block(int(tip_hash, 16), cb, tip["time"] + 1)
        bad.solve()
        return bad

    def run_test(self):
        n0, n1, n2 = self.nodes
        self.log.info("High-bandwidth path with product payload required")
        self.link_and_fill()

        self.log.info("A valid block still reaches the peers (deferred body delivered)")
        good = self.generate(n0, 1, sync_fun=self.no_op)[0]
        self.wait_until(lambda: n1.getbestblockhash() == good, timeout=20)
        self.wait_until(lambda: n2.getbestblockhash() == good, timeout=20)
        assert_equal(self.outbound_count(1), 1)
        assert_equal(self.outbound_count(2), 1)
        # The post-connect flush, not NewPoWValidBlock, emits this line now.
        assert self.log_has(0, f"sending full block {good}")

        self.log.info("An invalid tip child does not disconnect the honest relays")
        bad = self.bad_tip_child(n0)
        m = n0.add_p2p_connection(P2PDataStore())
        m.send_message(msg_block(bad))
        self.wait_until(lambda: self.tip_status(0, bad.hash) == "invalid", timeout=20)
        time.sleep(5)  # allow any (unwanted) relay + punishment to unfold
        assert_equal(self.outbound_count(1), 1)
        assert_equal(self.outbound_count(2), 1)
        assert self.tip_status(1, bad.hash) in ("headers-only", "unseen")
        assert self.tip_status(2, bad.hash) in ("headers-only", "unseen")
        # node0 never pushed the unconnected bad body, so no peer validated it.
        assert not self.log_has(0, f"sending full block {bad.hash}")
        assert not self.log_has(1, f"ConnectBlock {bad.hash}")

        self.log.info("With the payload flag off, the compact path still punishes no one")
        for i in range(3):
            self.restart_node(i, extra_args=self.node_args(0))
        self.link_and_fill()
        bad2 = self.bad_tip_child(n0)
        m2 = n0.add_p2p_connection(P2PDataStore())
        m2.send_message(msg_block(bad2))
        self.wait_until(lambda: self.tip_status(0, bad2.hash) == "invalid", timeout=20)
        time.sleep(5)
        assert_equal(self.outbound_count(1), 1)
        assert_equal(self.outbound_count(2), 1)


if __name__ == "__main__":
    UnconnectedBlockRelayTest(__file__).main()
