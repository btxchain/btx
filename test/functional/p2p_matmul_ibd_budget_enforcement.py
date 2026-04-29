#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ensure MatMul header sync continues during IBD."""

from test_framework.messages import CBlockHeader, from_hex, msg_headers
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMulIBDBudgetEnforcementTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-test=matmulstrict", "-debug=net"],
            ["-test=matmulstrict", "-debug=net"],
        ]

    def run_test(self):
        node0, node1 = self.nodes

        # Keep node1 in IBD and mine a batch of candidate headers on node0.
        self.disconnect_nodes(0, 1)
        for _ in range(21):
            self.generate(node0, 100, sync_fun=self.no_op)
        self.generate(node0, 5, sync_fun=self.no_op)
        assert_equal(node1.getblockcount(), 0)

        headers = []
        for height in range(1, 2106):
            block_hash = node0.getblockhash(height)
            headers.append(from_hex(CBlockHeader(), node0.getblockheader(block_hash, False)))

        attacker = node1.add_p2p_connection(P2PInterface())
        attacker.send_message(msg_headers(headers=headers[:2000]))
        attacker.sync_with_ping(timeout=20)
        attacker.send_message(msg_headers(headers=headers[2000:]))
        attacker.sync_with_ping(timeout=20)
        attacker.wait_until(
            lambda: node1.getblockchaininfo()["headers"] == 2105,
            timeout=20,
            check_connected=False,
        )
        attacker.wait_until(
            lambda: attacker.last_message.get("getheaders") is not None,
            timeout=20,
        )
        assert attacker.is_connected

        headers_only_tip = next(tip for tip in node1.getchaintips() if tip["hash"] == node0.getblockhash(2105))
        assert_equal(headers_only_tip["height"], 2105)
        assert_equal(headers_only_tip["status"], "headers-only")

        # The peer only supplied headers, so node1 stays at genesis tip.
        assert_equal(node1.getblockcount(), 0)


if __name__ == "__main__":
    BTXMatMulIBDBudgetEnforcementTest(__file__).main()
