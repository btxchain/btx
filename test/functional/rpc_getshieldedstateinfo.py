#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getshieldedstateinfo RPC."""

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class GetShieldedStateInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def run_test(self):
        node = self.nodes[0]
        res = node.getshieldedstateinfo()

        assert_equal(set(res.keys()), {
            "height",
            "bestblockhash",
            "shielded_state_initialized",
            "pool_balance",
            "pool_balance_sat",
            "next_block_height",
            "velocity_cap_active",
            "velocity_activation_height",
            "velocity_window_blocks",
            "velocity_window_lower_exclusive",
            "velocity_window_upper_inclusive",
            "velocity_cap_bps",
            "velocity_cap_amount",
            "velocity_cap_amount_sat",
            "velocity_window_egress",
            "velocity_window_egress_sat",
            "remaining_window_capacity",
            "remaining_window_capacity_sat",
            "velocity_window_exceeds_cap",
        })
        assert_equal(res["height"], node.getblockcount())
        assert_equal(res["bestblockhash"], node.getbestblockhash())
        assert_equal(res["next_block_height"], res["height"] + 1)
        assert_equal(res["velocity_window_upper_inclusive"], res["next_block_height"])
        assert_equal(
            res["velocity_window_lower_exclusive"],
            res["next_block_height"] - res["velocity_window_blocks"],
        )
        assert_equal(int(res["pool_balance"] * COIN), res["pool_balance_sat"])
        assert_equal(int(res["velocity_cap_amount"] * COIN), res["velocity_cap_amount_sat"])
        assert_equal(int(res["velocity_window_egress"] * COIN), res["velocity_window_egress_sat"])
        assert_equal(int(res["remaining_window_capacity"] * COIN), res["remaining_window_capacity_sat"])
        assert_equal(res["remaining_window_capacity_sat"], max(
            res["velocity_cap_amount_sat"] - res["velocity_window_egress_sat"],
            0,
        ))
        assert_equal(
            res["velocity_window_exceeds_cap"],
            res["velocity_window_egress_sat"] > res["velocity_cap_amount_sat"],
        )
        assert_equal(res["pool_balance_sat"], 0)
        assert_equal(res["velocity_window_egress_sat"], 0)
        assert isinstance(res["shielded_state_initialized"], bool)
        assert isinstance(res["velocity_cap_active"], bool)


if __name__ == "__main__":
    GetShieldedStateInfoTest(__file__).main()
