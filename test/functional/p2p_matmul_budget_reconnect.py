#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ensure MatMul header processing survives peer reconnects."""

from test_framework.messages import CBlockHeader, from_hex, msg_headers
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMulBudgetReconnectTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-test=matmulstrict", "-test=matmuldgw", "-debug=net", "-disablewallet=1"],
            ["-test=matmulstrict", "-test=matmuldgw", "-debug=net", "-disablewallet=1"],
        ]

    def run_test(self):
        node0, node1 = self.nodes

        # Anchor both nodes to the same initial chain so incoming headers start
        # after the fast-phase boundary (height >= 2) and use the normal budget.
        self.generate(node0, 3)

        # Keep node1 out of IBD so the normal (small) per-minute budget applies.
        self.disconnect_nodes(0, 1)
        self.generate(node1, 20, sync_fun=self.no_op)
        assert_equal(node1.getblockchaininfo()["initialblockdownload"], False)

        # Build an alternate valid header chain from node0.
        self.generate(node0, 40, sync_fun=self.no_op)
        headers = []
        for height in range(4, 44):
            block_hash = node0.getblockhash(height)
            headers.append(from_hex(CBlockHeader(), node0.getblockheader(block_hash, False)))

        # Prime per-address budget usage.
        attacker = node1.add_p2p_connection(P2PInterface())
        attacker.send_message(msg_headers(headers=headers[:10]))
        attacker.sync_with_ping(timeout=20)

        # Reconnect from the same address.
        attacker.peer_disconnect()
        attacker.wait_for_disconnect(timeout=10)
        attacker = node1.add_p2p_connection(P2PInterface())

        # The remaining headers should continue to be processed after reconnect.
        # Keep the assertion state-based so the test remains stable if budget
        # accounting or logging changes without affecting chain progress.
        attacker.send_message(msg_headers(headers=headers[10:]))
        attacker.sync_with_ping(timeout=20)
        attacker.wait_until(
            lambda: node1.getblockchaininfo()["headers"] == 43,
            timeout=20,
            check_connected=False,
        )
        assert attacker.is_connected
        with p2p_lock:
            getdata = attacker.last_message.get("getdata")
            assert getdata is not None
            requested_hashes = [inv.hash for inv in getdata.inv]
        expected_hashes = {header.rehash() for header in headers[10:]}
        assert any(block_hash in expected_hashes for block_hash in requested_hashes)

        headers_only_tip = next(tip for tip in node1.getchaintips() if tip["hash"] == node0.getblockhash(43))
        assert_equal(headers_only_tip["height"], 43)
        assert_equal(headers_only_tip["status"], "headers-only")


if __name__ == "__main__":
    BTXMatMulBudgetReconnectTest(__file__).main()
