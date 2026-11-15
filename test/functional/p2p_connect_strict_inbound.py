#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""-connect=<ip> keeps the strict inbound mode.

A node that names a -connect target skips SendMessages for its inbound,
non-manual peers (CConnman::ThreadMessageHandler). This pins that mode, so
the -connect=0 change checked by p2p_noconnect_inbound_relay.py does not
widen to nodes that name a target:

- the strict node's -connect target still gets the new block;
- a normal node announces the same block to its inbound test peer (control);
- the strict node announces nothing to its inbound test peer, yet still
  answers that peer's pings, because ProcessMessages keeps running.
"""

from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class BlockAnnounceWatcher(P2PInterface):
    """Record every block hash this peer hears about, by any message."""

    def __init__(self):
        super().__init__()
        self.block_hashes = set()

    def on_headers(self, message):
        for header in message.headers:
            self.block_hashes.add(header.rehash())

    def on_inv(self, message):
        super().on_inv(message)
        for inv in message.inv:
            self.block_hashes.add(inv.hash)

    def on_block(self, message):
        self.block_hashes.add(message.block.rehash())

    def on_cmpctblock(self, message):
        self.block_hashes.add(message.header_and_shortids.header.rehash())

    def heard_of(self, block_hash):
        with p2p_lock:
            return int(block_hash, 16) in self.block_hashes


class StrictConnectInboundTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # This test sets -connect itself instead of the framework's connect=0.
        self.disable_autoconnect = False

    def setup_network(self):
        # node0 names node1 as its only -connect target (strict mode).
        # node1 has no -connect setting; with no seeds it makes no
        # outbound connections of its own.
        # -modelbind=off keeps the two btx-modeld helpers off the shared
        # PQ1 port.
        self.extra_args = [
            ["-modelbind=off", f"-connect=127.0.0.1:{p2p_port(1)}"],
            ["-modelbind=off"],
        ]
        self.setup_nodes()
        self.wait_until(lambda: len(self.nodes[0].getpeerinfo()) == 1)
        self.wait_until(lambda: len(self.nodes[1].getpeerinfo()) == 1)

    def run_test(self):
        strict, target = self.nodes
        (link,) = strict.getpeerinfo()
        assert not link["inbound"]
        assert_equal(link["connection_type"], "manual")

        strict_peer = strict.add_p2p_connection(BlockAnnounceWatcher())
        control_peer = target.add_p2p_connection(BlockAnnounceWatcher())
        inbound = [p for p in strict.getpeerinfo() if p["inbound"]]
        assert_equal(len(inbound), 1)
        assert_equal(inbound[0]["connection_type"], "inbound")

        self.log.info("Mine one block on the strict node")
        block_hash = self.generate(strict, 1, sync_fun=self.no_op)[0]

        self.log.info("The -connect target gets it")
        self.sync_blocks()

        self.log.info("A normal node announces it to its inbound peer (control)")
        self.wait_until(lambda: control_peer.heard_of(block_hash))

        self.log.info("The strict node announces nothing to its inbound peer, but answers its pings")
        strict_peer.sync_with_ping()
        strict_peer.sync_with_ping()
        assert not strict_peer.heard_of(block_hash)
        assert_equal(len([p for p in strict.getpeerinfo() if p["inbound"]]), 1)


if __name__ == "__main__":
    StrictConnectInboundTest(__file__).main()
