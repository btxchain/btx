#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest rehearsal for BTX MatMul binding and ASERT upgrade boundaries."""

from test_framework.messages import uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMulActivationRehearsal(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            "-regtestmatmulbindingheight=5",
            "-regtestmatmulproductdigestheight=5",
            "-regtestmatmulrequireproductpayload=0",
        ]
        self.extra_args = [
            [
                *common,
                "-regtestmatmulaserthalflifeupgradeheight=10",
                "-regtestmatmulaserthalflifeupgrade=3600",
                "-regtestmatmulprehashepsilonbitsupgradeheight=10",
                "-regtestmatmulprehashepsilonbitsupgrade=6",
            ],
            common,
        ]

    def mine_at(self, node, mock_time):
        node.setmocktime(mock_time)
        block = node.generateblock("raw(51)", [], called_by_framework=True)
        block_hash = block["hash"]
        return node.getblock(block_hash, 2)

    @staticmethod
    def target_from_bits(bits_hex):
        return uint256_from_compact(int(bits_hex, 16))

    def run_test(self):
        upgraded, control = self.nodes
        self.disconnect_nodes(0, 1)

        genesis_time = upgraded.getblockheader(upgraded.getblockhash(0))["time"]
        upgraded_time = genesis_time
        control_time = genesis_time

        pre_binding_blocks = []
        for expected_height in range(1, 5):
            upgraded_time += 90
            control_time += 90
            upgraded_block = self.mine_at(upgraded, upgraded_time)
            self.mine_at(control, control_time)
            assert_equal(upgraded_block["height"], expected_height)
            pre_binding_blocks.append(upgraded_block)

        for block in pre_binding_blocks:
            assert "matrix_c_words" not in block

        pre_binding_health = upgraded.getdifficultyhealth(4)
        assert_equal(pre_binding_health["consensus_guards"]["freivalds_transcript_binding"]["active"], False)
        assert_equal(pre_binding_health["consensus_guards"]["freivalds_transcript_binding"]["remaining_blocks"], 1)
        assert_equal(pre_binding_health["consensus_guards"]["freivalds_payload_mining"]["enabled"], True)
        # The profile reports the requirement for the next block to be mined.
        assert_equal(pre_binding_health["consensus_guards"]["freivalds_payload_mining"]["required_by_consensus"], True)

        upgraded_time += 90
        control_time += 90
        binding_block = self.mine_at(upgraded, upgraded_time)
        self.mine_at(control, control_time)
        assert_equal(binding_block["height"], 5)
        assert "matrix_c_words" in binding_block
        assert binding_block["matrix_c_words"] > 0

        post_binding_health = upgraded.getdifficultyhealth(5)
        assert_equal(post_binding_health["consensus_guards"]["freivalds_transcript_binding"]["active"], True)
        assert_equal(post_binding_health["consensus_guards"]["freivalds_transcript_binding"]["remaining_blocks"], 0)
        assert_equal(post_binding_health["consensus_guards"]["freivalds_payload_mining"]["enabled"], True)
        assert_equal(post_binding_health["consensus_guards"]["freivalds_payload_mining"]["required_by_consensus"], True)

        while upgraded.getblockcount() < 9:
            upgraded_time += 90
            control_time += 90
            self.mine_at(upgraded, upgraded_time)
            self.mine_at(control, control_time)

        pre_upgrade_health = upgraded.getdifficultyhealth(9)
        assert_equal(pre_upgrade_health["consensus_guards"]["asert_half_life"]["current_s"], 14400)
        assert_equal(pre_upgrade_health["consensus_guards"]["asert_half_life"]["upgrade_active"], False)
        assert_equal(pre_upgrade_health["consensus_guards"]["asert_half_life"]["upgrade_height"], 10)
        assert_equal(pre_upgrade_health["consensus_guards"]["asert_half_life"]["remaining_blocks"], 1)
        assert_equal(pre_upgrade_health["consensus_guards"]["pre_hash_epsilon_bits"]["current_bits"], 0)
        assert_equal(pre_upgrade_health["consensus_guards"]["pre_hash_epsilon_bits"]["next_block_bits"], 6)
        assert_equal(pre_upgrade_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_active"], False)
        assert_equal(pre_upgrade_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_height"], 10)
        assert_equal(pre_upgrade_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_bits"], 6)
        assert_equal(pre_upgrade_health["consensus_guards"]["pre_hash_epsilon_bits"]["remaining_blocks"], 1)

        parent_bits = upgraded.getblockheader(upgraded.getbestblockhash())["bits"]

        upgraded_time += 90
        control_time += 90
        activation_block = self.mine_at(upgraded, upgraded_time)
        self.mine_at(control, control_time)
        assert_equal(activation_block["height"], 10)
        assert_equal(activation_block["bits"], parent_bits)

        activation_health = upgraded.getdifficultyhealth(10)
        assert_equal(activation_health["consensus_guards"]["asert_half_life"]["current_s"], 3600)
        assert_equal(activation_health["consensus_guards"]["asert_half_life"]["upgrade_active"], True)
        assert_equal(activation_health["consensus_guards"]["asert_half_life"]["remaining_blocks"], 0)
        assert_equal(activation_health["consensus_guards"]["pre_hash_epsilon_bits"]["current_bits"], 6)
        assert_equal(activation_health["consensus_guards"]["pre_hash_epsilon_bits"]["next_block_bits"], 6)
        assert_equal(activation_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_active"], True)
        assert_equal(activation_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_height"], 10)
        assert_equal(activation_health["consensus_guards"]["pre_hash_epsilon_bits"]["remaining_blocks"], 0)
        assert_equal(upgraded.getmatmulchallenge()["work_profile"]["pre_hash_epsilon_bits"], 6)

        control_health = control.getdifficultyhealth(10)
        assert_equal(control_health["consensus_guards"]["asert_half_life"]["current_s"], 14400)
        assert_equal(control_health["consensus_guards"]["asert_half_life"]["upgrade_active"], False)
        assert_equal(control_health["consensus_guards"]["asert_half_life"]["upgrade_height"], -1)
        assert_equal(control_health["consensus_guards"]["pre_hash_epsilon_bits"]["current_bits"], 0)
        assert_equal(control_health["consensus_guards"]["pre_hash_epsilon_bits"]["next_block_bits"], 0)
        assert_equal(control_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_active"], False)
        assert_equal(control_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_height"], -1)
        assert_equal(control_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_bits"], 0)

        upgraded_time += 30
        control_time += 30
        post_upgrade_block = self.mine_at(upgraded, upgraded_time)
        control_post_upgrade_block = self.mine_at(control, control_time)
        assert_equal(post_upgrade_block["height"], 11)
        assert_equal(control_post_upgrade_block["height"], 11)

        upgraded_target = self.target_from_bits(post_upgrade_block["bits"])
        control_target = self.target_from_bits(control_post_upgrade_block["bits"])
        assert upgraded_target < control_target

        prehash_active_health = upgraded.getdifficultyhealth(11)
        assert_equal(prehash_active_health["consensus_guards"]["pre_hash_epsilon_bits"]["current_bits"], 6)
        assert_equal(prehash_active_health["consensus_guards"]["pre_hash_epsilon_bits"]["next_block_bits"], 6)
        assert_equal(prehash_active_health["consensus_guards"]["pre_hash_epsilon_bits"]["upgrade_active"], True)
        assert_equal(prehash_active_health["consensus_guards"]["pre_hash_epsilon_bits"]["remaining_blocks"], 0)
        assert_equal(upgraded.getmatmulchallenge()["work_profile"]["pre_hash_epsilon_bits"], 6)
        assert_equal(control.getdifficultyhealth(11)["consensus_guards"]["pre_hash_epsilon_bits"]["current_bits"], 0)

        upgraded.setmocktime(0)
        control.setmocktime(0)


if __name__ == "__main__":
    BTXMatMulActivationRehearsal(__file__).main()
