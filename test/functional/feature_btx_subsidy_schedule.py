#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BTX subsidy parameter checks on regtest genesis."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXSubsidyScheduleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def run_test(self):
        node = self.nodes[0]

        info = node.getblockchaininfo()
        assert_equal(info["chain"], "regtest")
        assert_equal(info["blocks"], 0)

        genesis_hash = node.getblockhash(0)
        stats = node.getblockstats(genesis_hash)
        assert_equal(stats["height"], 0)
        assert_equal(stats["subsidy"], 20 * 100_000_000)

        header = node.getblockheader(genesis_hash)
        assert_equal(header["bits"], "207fffff")
        assert_equal(header["height"], 0)


if __name__ == "__main__":
    BTXSubsidyScheduleTest(__file__).main()
