#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ensure inbound peers are disconnected for MatMul Phase1-pass/Phase2-fail blocks."""

from test_framework.messages import CBlock, from_hex, msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMulInboundPunishmentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-test=matmulstrict"]]

    def _phase1_pass_phase2_fail_block(self, node):
        candidate = node.generateblock("raw(51)", [], False, called_by_framework=True)
        block = from_hex(CBlock(), candidate["hex"])
        # Keep deterministic seeds untouched (consensus now rejects mismatched
        # seeds before Phase2), and instead corrupt the Phase2 transcript.
        block.matmul_digest ^= 1
        if block.matmul_digest == 0:
            block.matmul_digest = 1
        return block

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 20)

        attacker = node.add_p2p_connection(P2PInterface())
        assert_equal(node.getconnectioncount(), 1)

        bad_block = self._phase1_pass_phase2_fail_block(node)
        attacker.send_message(msg_block(bad_block))
        attacker.wait_for_disconnect(timeout=10)
        self.wait_until(lambda: node.getconnectioncount() == 0, timeout=10)


if __name__ == "__main__":
    BTXMatMulInboundPunishmentTest(__file__).main()
