#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise the post-activation payload boundary on a short regtest activation.

The literal 60999 -> 61000 semantics are covered in pow_tests. This functional
keeps the same consensus behavior, but moves the regtest activation to a tiny
height so the end-to-end boundary remains practical for the default suite.
"""

from test_framework.messages import (
    CBlock,
    from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMul61000BoundaryTest(BitcoinTestFramework):
    ACTIVATION_HEIGHT = 5

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        common = [
            "-test=matmulstrict",
            f"-regtestmatmulbindingheight={self.ACTIVATION_HEIGHT}",
            f"-regtestmatmulproductdigestheight={self.ACTIVATION_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
        ]
        self.extra_args = [common, common]

    def mine_to_height(self, node, target_height, chunk_size=1000):
        while node.getblockcount() < target_height:
            remaining = target_height - node.getblockcount()
            self.generate(node, min(chunk_size, remaining), sync_fun=self.no_op)

    def run_test(self):
        rejecting_node, accepting_node = self.nodes
        self.disconnect_nodes(0, 1)
        pre_activation_height = self.ACTIVATION_HEIGHT - 1
        post_activation_height = self.ACTIVATION_HEIGHT + 1

        self.log.info("Mining cleanly to the block before activation with pre-activation transcript digest rules")
        self.mine_to_height(rejecting_node, pre_activation_height)
        self.mine_to_height(accepting_node, pre_activation_height)
        assert_equal(rejecting_node.getblockcount(), pre_activation_height)
        assert_equal(accepting_node.getblockcount(), pre_activation_height)

        pre_boundary_block = accepting_node.getblock(accepting_node.getblockhash(pre_activation_height), 2)
        assert "matrix_c_words" not in pre_boundary_block

        pre_boundary_health = accepting_node.getdifficultyhealth(pre_activation_height)
        assert_equal(pre_boundary_health["consensus_guards"]["freivalds_transcript_binding"]["active"], False)
        assert_equal(pre_boundary_health["consensus_guards"]["freivalds_transcript_binding"]["remaining_blocks"], 1)
        assert_equal(pre_boundary_health["consensus_guards"]["freivalds_payload_mining"]["enabled"], True)
        assert_equal(pre_boundary_health["consensus_guards"]["freivalds_payload_mining"]["required_by_consensus"], True)

        self.log.info("Asserting that the activation block rejects payloadless blocks and accepts the full block")
        tip_hash = rejecting_node.getbestblockhash()
        invalid_candidate = rejecting_node.generateblock("raw(51)", [], False, called_by_framework=True)
        payloadless_hex = from_hex(CBlock(), invalid_candidate["hex"]).serialize().hex()

        assert len(invalid_candidate["hex"]) >= len(payloadless_hex)
        assert_equal(rejecting_node.submitblock(payloadless_hex), "missing-product-payload")
        assert_equal(rejecting_node.getbestblockhash(), tip_hash)

        candidate = accepting_node.generateblock("raw(51)", [], False, called_by_framework=True)
        assert_equal(accepting_node.submitblock(candidate["hex"]), None)
        assert_equal(accepting_node.getbestblockhash(), candidate["hash"])

        activation_block = accepting_node.getblock(candidate["hash"], 2)
        assert_equal(activation_block["height"], self.ACTIVATION_HEIGHT)
        assert activation_block["matrix_c_words"] > 0

        activation_health = accepting_node.getdifficultyhealth(self.ACTIVATION_HEIGHT)
        assert_equal(activation_health["consensus_guards"]["freivalds_transcript_binding"]["active"], True)
        assert_equal(activation_health["consensus_guards"]["freivalds_transcript_binding"]["remaining_blocks"], 0)
        assert_equal(activation_health["consensus_guards"]["freivalds_payload_mining"]["enabled"], True)
        assert_equal(activation_health["consensus_guards"]["freivalds_payload_mining"]["required_by_consensus"], True)

        self.log.info("Mining one more block to prove post-activation mining continues")
        post_activation = accepting_node.generateblock("raw(51)", [], called_by_framework=True)
        post_activation_block = accepting_node.getblock(post_activation["hash"], 2)
        assert_equal(post_activation_block["height"], post_activation_height)
        assert post_activation_block["matrix_c_words"] > 0
        assert_equal(accepting_node.getblockcount(), post_activation_height)


if __name__ == "__main__":
    BTXMatMul61000BoundaryTest(__file__).main()
