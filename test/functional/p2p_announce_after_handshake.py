#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A new block must be announced to a peer that connected after the last block.

Node 0 dials node 1, so node 0 is node 1's inbound peer. The initial
getheaders exchange completes with nothing new (both share the cached
chain). Node 1 then mines one block. Node 0 must learn about it from node
1's announcement (inv, headers or cmpctblock), without another block or a
fresh getheaders. --miner-dials runs the same check with node 1 dialing,
so node 0 is node 1's outbound peer.
"""
import time

from test_framework.test_framework import BitcoinTestFramework


class AnnounceAfterHandshakeTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--rounds", type=int, default=3)
        parser.add_argument("--settle", type=float, default=1.0,
                            help="seconds between connect and mining (lets the getheaders exchange finish)")
        parser.add_argument("--miner-dials", action="store_true",
                            help="the mining node opens the connection (announce to an outbound peer)")

    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()  # start unconnected; both share the cached chain

    def run_test(self):
        n0, n1 = self.nodes
        missed = 0
        for i in range(self.options.rounds):
            if self.options.miner_dials:
                self.connect_nodes(1, 0)
            else:
                self.connect_nodes(0, 1)
            time.sleep(self.options.settle)
            block = self.generate(n1, 1, sync_fun=self.no_op)[0]
            deadline = time.time() + 20
            while time.time() < deadline and n0.getbestblockhash() != block:
                time.sleep(0.2)
            got = n0.getbestblockhash() == block
            self.log.info(f"round {i}: node0 {'received' if got else 'DID NOT receive'} block {block[:16]} within 20 s")
            if not got:
                missed += 1
                # resync before the next round: ask node0 to fetch it via a fresh connection
                self.disconnect_nodes(0, 1)
                self.connect_nodes(0, 1)
                self.sync_blocks(timeout=60)
            self.disconnect_nodes(0, 1)
        self.log.info(f"RESULT missed={missed} rounds={self.options.rounds}")
        assert missed == 0, f"{missed} of {self.options.rounds} blocks were not announced to the fresh peer"


if __name__ == '__main__':
    AnnounceAfterHandshakeTest(__file__).main()
