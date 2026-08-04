#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that -connect and -addnode do not open duplicate manual connections."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


def outbound_manual_peers(node):
    return [
        peer for peer in node.getpeerinfo()
        if not peer["inbound"] and peer["connection_type"] == "manual"
    ]


def inbound_peers(node):
    return [peer for peer in node.getpeerinfo() if peer["inbound"]]


class DuplicateManualConnectionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.disable_autoconnect = False
        self.extra_args = [
            ["-listen=1", f"-connect=127.0.0.1:{p2p_port(1)}", f"-addnode=127.0.0.1:{p2p_port(1)}"],
            ["-listen=1", f"-connect=127.0.0.1:{p2p_port(0)}", f"-addnode=127.0.0.1:{p2p_port(0)}"],
        ]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.wait_until(lambda: all(
            len(inbound_peers(node)) >= 1 and len(outbound_manual_peers(node)) >= 1
            for node in self.nodes
        ))
        self.wait_until(lambda: all(node.getconnectioncount() >= 2 for node in self.nodes))

        for node in self.nodes:
            assert_equal(len(inbound_peers(node)), 1)
            assert_equal(len(outbound_manual_peers(node)), 1)
            assert_equal(node.getconnectioncount(), 2)


if __name__ == "__main__":
    DuplicateManualConnectionsTest(__file__).main()
