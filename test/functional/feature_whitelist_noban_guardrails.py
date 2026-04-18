#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Whitelist noban hardening and default permission semantics."""

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework


class BTXWhitelistNoBanGuardrailsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        self.stop_node(0)

        node.assert_start_raises_init_error(
            extra_args=["-whitelist=noban@0.0.0.0/0"],
            expected_msg="Error: Refusing broad -whitelist=noban range '0.0.0.0/0' without -allowdangerousnoban=1",
        )

        self.start_node(
            0,
            extra_args=[
                "-allowdangerousnoban=1",
                "-whitelist=noban@0.0.0.0/0",
            ],
        )
        self.stop_node(
            0,
            expected_stderr="Warning: Dangerous configuration: broad -whitelist=noban range '0.0.0.0/0' enabled by -allowdangerousnoban=1",
        )

        # Implicit whitelist permissions no longer include noban.
        self.start_node(0, extra_args=["-whitelist=127.0.0.1/32"])
        peer = node.add_p2p_connection(P2PInterface())
        perms = node.getpeerinfo()[0]["permissions"]
        assert "noban" not in perms
        assert "download" in perms
        peer.peer_disconnect()
        self.wait_until(lambda: node.getconnectioncount() == 0, timeout=10)
        self.stop_node(0)

        # Explicit narrow noban remains supported without override.
        self.start_node(0, extra_args=["-whitelist=noban@127.0.0.1/32"])
        peer = node.add_p2p_connection(P2PInterface())
        perms = node.getpeerinfo()[0]["permissions"]
        assert "noban" in perms
        peer.peer_disconnect()


if __name__ == "__main__":
    BTXWhitelistNoBanGuardrailsTest(__file__).main()
