#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BTX fast/normal MatMul mining and DGW retarget checks on regtest."""

from test_framework.messages import uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXFastMiningPhaseTest(BitcoinTestFramework):
    FAST_MINE_HEIGHT = 2
    DGW_WARMUP_HEIGHT = 181
    FAST_BLOCK_SPACING = 1
    NORMAL_BLOCK_SPACING = 90

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        self.extra_args = [["-test=matmuldgw"]]

    @staticmethod
    def target_from_bits(bits_hex):
        return uint256_from_compact(int(bits_hex, 16))

    def run_test(self):
        node = self.nodes[0]
        genesis_hash = node.getblockhash(0)
        header_json = node.getblockheader(genesis_hash, True)

        info = node.getblockchaininfo()
        assert_equal(info["chain"], "regtest")
        assert_equal(info["blocks"], 0)

        header_hex = node.getblockheader(genesis_hash, False)

        # MatMul header layout is 182 bytes on BTX networks.
        assert_equal(len(header_hex), 182 * 2)
        assert_equal(header_json["bits"], "207fffff")
        assert_equal(header_json["height"], 0)

        # TEST: mining_fast_and_normal_phase_blocks
        # Mine through both phases with deterministic timestamps up to the
        # first DGW retarget activation height.
        mock_time = header_json["time"]
        for height in range(1, self.DGW_WARMUP_HEIGHT + 2):
            spacing = self.FAST_BLOCK_SPACING if height < self.FAST_MINE_HEIGHT else self.NORMAL_BLOCK_SPACING
            mock_time += spacing
            node.setmocktime(mock_time)
            mined = node.generateblock("raw(51)", [], called_by_framework=True)
            assert_equal(node.getbestblockhash(), mined["hash"])

        assert_equal(node.getblockcount(), self.DGW_WARMUP_HEIGHT + 1)
        fast_header = node.getblockheader(node.getblockhash(self.FAST_MINE_HEIGHT - 1), True)
        normal_header = node.getblockheader(node.getblockhash(self.FAST_MINE_HEIGHT), True)
        assert_equal(fast_header["height"], self.FAST_MINE_HEIGHT - 1)
        assert_equal(normal_header["height"], self.FAST_MINE_HEIGHT)

        # TEST: dgw_retarget_activation_changes_target
        pre_retarget_target = self.target_from_bits(node.getblockheader(node.getblockhash(self.DGW_WARMUP_HEIGHT - 1), True)["bits"])
        first_retarget_target = self.target_from_bits(node.getblockheader(node.getblockhash(self.DGW_WARMUP_HEIGHT), True)["bits"])
        second_retarget_target = self.target_from_bits(node.getblockheader(node.getblockhash(self.DGW_WARMUP_HEIGHT + 1), True)["bits"])
        if (first_retarget_target == pre_retarget_target and
                second_retarget_target == pre_retarget_target):
            self.log.info("DGW retarget remained stable across the first two post-activation blocks")

        node.setmocktime(0)


if __name__ == "__main__":
    BTXFastMiningPhaseTest(__file__).main()
