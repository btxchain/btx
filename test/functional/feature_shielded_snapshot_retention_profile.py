#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the runtime shielded snapshot retention profile surface."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

WEEKLY_SNAPSHOT_TARGET_BYTES = 2642412320
WEEKLY_SNAPSHOT_TARGET_DAYS = 7
WEEKLY_SNAPSHOT_TARGET_BLOCKS = 6720
TARGET_SPACING_SECONDS = 90


class ShieldedSnapshotRetentionProfileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            [],
            ["-retainshieldedcommitmentindex=1"],
        ]

    def run_test(self):
        expectations = [
            ("externalized", False),
            ("full_commitment_index", True),
        ]

        for index, (profile, retain_commitment_index) in enumerate(expectations):
            node = self.nodes[index]
            self.log.info(f"Mine a mature chain on node {index} and dump a snapshot")
            self.generate(node, COINBASE_MATURITY + 1)

            blockchaininfo = node.getblockchaininfo()
            assert_equal(blockchaininfo["shielded_retention"]["profile"], profile)
            assert_equal(blockchaininfo["shielded_retention"]["retain_shielded_commitment_index"], retain_commitment_index)
            assert_equal(blockchaininfo["shielded_retention"]["snapshot_target_bytes"], WEEKLY_SNAPSHOT_TARGET_BYTES)
            assert_equal(blockchaininfo["shielded_retention"]["snapshot_target_days"], WEEKLY_SNAPSHOT_TARGET_DAYS)
            assert_equal(blockchaininfo["shielded_retention"]["snapshot_target_blocks"], WEEKLY_SNAPSHOT_TARGET_BLOCKS)
            assert_equal(blockchaininfo["shielded_retention"]["snapshot_target_spacing_seconds"], TARGET_SPACING_SECONDS)
            assert_equal(blockchaininfo["snapshot_sync"]["active"], False)
            assert_equal(blockchaininfo["snapshot_sync"]["background_validation_in_progress"], False)

            snapshot = node.dumptxoutset(f"shielded-retention-profile-{index}.dat", "latest")
            assert_equal(snapshot["shielded_retention_profile"], profile)
            assert_equal(snapshot["retain_shielded_commitment_index"], retain_commitment_index)


if __name__ == "__main__":
    ShieldedSnapshotRetentionProfileTest(__file__).main()
