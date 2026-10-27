#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""-connect=0 stops automatic outbound connections only.

The framework writes connect=0 into every node's config. A node in that mode
must still run SendMessages for its inbound peers after the handshake: an
inbound peer syncs to the tip of a burst, and the node sends the ping that
the ping RPC queues for that peer.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class NoConnectInboundRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Keep the two btx-modeld helpers off the shared PQ1 port.
        self.extra_args = [["-modelbind=off"], ["-modelbind=off"]]

    def setup_network(self):
        self.setup_nodes()
        # node1 dials node0, so node1 is an inbound peer of node0.
        self.connect_nodes(1, 0)

    @staticmethod
    def ping_bytes_sent(node):
        (peer,) = node.getpeerinfo()
        return peer["bytessent_per_msg"].get("ping", 0)

    def run_test(self):
        miner, follower = self.nodes
        assert all(peer["inbound"] for peer in miner.getpeerinfo())
        assert all(not peer["inbound"] for peer in follower.getpeerinfo())

        self.log.info("Mine a burst on the node whose only peer is inbound")
        self.generate(miner, 5, sync_fun=self.no_op)
        self.sync_blocks(timeout=60)
        assert_equal(follower.getbestblockhash(), miner.getbestblockhash())

        # The message-handler pass that completes the handshake can still
        # send the first automatic ping, so wait for its pong. After that,
        # only SendMessages sends the ping the RPC queues.
        self.log.info("The node sends a queued ping to its inbound peer")
        self.wait_until(lambda: "pingtime" in miner.getpeerinfo()[0])
        before = self.ping_bytes_sent(miner)
        miner.ping()
        self.wait_until(lambda: self.ping_bytes_sent(miner) > before)


if __name__ == "__main__":
    NoConnectInboundRelayTest(__file__).main()
