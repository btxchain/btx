#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end MatMul consensus checks."""

from test_framework.messages import (
    CBlock,
    from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMulConsensusTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            "-regtestmatmulbindingheight=5",
            "-regtestmatmulproductdigestheight=5",
            "-regtestmatmulrequireproductpayload=0",
        ]
        self.extra_args = [
            common,
            common,
            common,
        ]

    def run_test(self):
        node0, node1, node2 = self.nodes
        bootstrap_height = 4

        # Keep node2 behind for an explicit assumevalid sync pass later.
        self.disconnect_nodes(1, 2)
        # Under parallel CI load, the 0<->1 link can race during startup.
        # Ensure the pair is explicitly connected before sync waits.
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 0)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )

        # Keep bootstrap sync below strict per-peer MatMul verification budget
        # to avoid localhost budget-sharing disconnects in parallel CI.
        self.generate(node0, bootstrap_height, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() >= node0.getblockcount()
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )

        tip_hash = node0.getbestblockhash()
        assert_equal(node1.getbestblockhash(), tip_hash)
        assert_equal(node0.getblockcount(), bootstrap_height)
        assert_equal(node1.getblockcount(), bootstrap_height)
        assert_equal(node2.getblockcount(), 0)
        for height in range(1, bootstrap_height + 1):
            block = node0.getblock(node0.getblockhash(height), 2)
            assert "matrix_c_words" not in block

        candidate = node0.generateblock("raw(51)", [], False, called_by_framework=True)
        good_hex = candidate["hex"]
        digest_start = (4 + 32 + 32 + 4 + 4 + 8) * 2
        digest_end = digest_start + 64
        bad_hex = good_hex[:digest_start] + ("f" * 64) + good_hex[digest_end:]
        assert_equal(node1.submitblock(bad_hex), "high-hash")
        assert_equal(node1.getbestblockhash(), tip_hash)

        # A fully populated MatMul block remains acceptable under strict regtest.
        assert_equal(node1.submitblock(good_hex), None)
        self.wait_until(
            lambda: node0.getbestblockhash() == node1.getbestblockhash(),
            timeout=180,
        )
        tip_hash = node1.getbestblockhash()

        activated_block = node1.getblock(tip_hash, 2)
        assert activated_block["height"] >= 5
        assert activated_block["matrix_c_words"] > 0

        # Live-style activation keeps payloads optional before the boundary,
        # but once the product-committed digest activates they become
        # consensus-required.
        payload_candidate = node0.generateblock("raw(51)", [], False, called_by_framework=True)
        payload_full_hex = payload_candidate["hex"]
        parsed_block = from_hex(CBlock(), payload_full_hex)
        # test_framework CBlock serializes header+tx only.
        payloadless_hex = parsed_block.serialize().hex()
        assert len(payload_full_hex) >= len(payloadless_hex)
        assert_equal(node1.submitblock(payloadless_hex), "missing-product-payload")
        assert_equal(node1.getbestblockhash(), tip_hash)

        assume_hash = node0.getblockhash(bootstrap_height // 2)
        self.restart_node(
            2,
            extra_args=[
                "-test=matmuldgw",
                "-regtestmatmulbindingheight=5",
                "-regtestmatmulproductdigestheight=5",
                "-regtestmatmulrequireproductpayload=0",
                f"-assumevalid={assume_hash}",
            ],
        )
        self.connect_nodes(2, 0)
        self.wait_until(
            lambda: node2.getblockcount() >= node0.getblockcount()
            and node2.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )
        assert_equal(node2.getbestblockhash(), tip_hash)


if __name__ == "__main__":
    BTXMatMulConsensusTest(__file__).main()
