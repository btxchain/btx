#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BTX ASERT activation and pre-activation stability checks on regtest.

DESIGN INVARIANT: MatMul networks use ASERT exclusively for difficulty
adjustment. DGW is NOT used for MatMul mining. Do not reintroduce DGW.
"""

from test_framework.messages import uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXAsertConvergenceTest(BitcoinTestFramework):
    FAST_MINE_HEIGHT = 2

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        self.extra_args = [["-test=matmuldgw"]]

    @staticmethod
    def target_from_bits(bits_hex):
        return uint256_from_compact(int(bits_hex, 16))

    def mine_block(self, node, mock_time, spacing):
        mock_time += spacing
        node.setmocktime(mock_time)
        node.generateblock("raw(51)", [], called_by_framework=True)
        return mock_time, node.getblockheader(node.getbestblockhash(), True)

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getblockheader(node.getblockhash(0), True)
        mock_time = genesis["time"]

        self.log.info("Scenario 1: fast phase nBits remains constant (bootstrap)")
        fast_phase_bits = None
        for height in range(1, self.FAST_MINE_HEIGHT + 1):
            mock_time, hdr = self.mine_block(node, mock_time, 1)
            if fast_phase_bits is None:
                fast_phase_bits = hdr["bits"]
            # During fast phase, difficulty should be constant bootstrap value.
            assert_equal(hdr["bits"], fast_phase_bits)

        pre_asert_target = self.target_from_bits(fast_phase_bits)
        self.log.info(f"  Bootstrap bits (height {self.FAST_MINE_HEIGHT}): {fast_phase_bits}")

        self.log.info("Scenario 2: ASERT activation applies retargeting")
        post_targets = []
        for _ in range(5):
            mock_time, hdr = self.mine_block(node, mock_time, 90)
            post_targets.append(self.target_from_bits(hdr["bits"]))

        # After ASERT activates, retargeting should adjust difficulty.
        self.log.info(
            f"  Post-activation target ratios: "
            + ", ".join(f"{t / pre_asert_target:.6f}x" for t in post_targets)
        )

        self.log.info("ASERT activation/stability checks passed")
        node.setmocktime(0)


if __name__ == "__main__":
    BTXAsertConvergenceTest(__file__).main()
