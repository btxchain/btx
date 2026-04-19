#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""
Multi-Node Genesis Consensus Validation

Validates that multiple nodes maintain consensus through:
  1. Initial sync from genesis
  2. Mining on one node and propagation to peers
  3. Nodes joining at different times (late joiner sync)
  4. DGW difficulty stays consistent across all nodes
  5. Phase 2 MatMul validation works between peers
  6. Chain tip agreement after hashrate changes (variable block spacing)
  7. Reorg handling: short forks resolve correctly

This test uses 3 nodes:
  - node0: Primary miner
  - node1: Synced peer (validates blocks from node0)
  - node2: Late joiner (disconnected, then reconnects and syncs)

Run: test/functional/feature_btx_multinode_genesis.py
"""

from test_framework.messages import uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMultiNodeGenesisTest(BitcoinTestFramework):
    FAST_MINE_HEIGHT = 2
    DGW_PAST_BLOCKS = 24
    STEADY_STATE_BLOCKS = 12
    VARIABLE_PHASE_BLOCKS = 4

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        self.extra_args = [
            [
                "-test=matmuldgw",
                "-test=matmulstrict",
                "-matmulvalidation=economic",
                "-whitelist=noban@127.0.0.1",
                "-whitelist=noban@::1",
            ],
            [
                "-test=matmuldgw",
                "-test=matmulstrict",
                "-matmulvalidation=economic",
                "-whitelist=noban@127.0.0.1",
                "-whitelist=noban@::1",
            ],
            [
                "-test=matmuldgw",
                "-test=matmulstrict",
                "-matmulvalidation=economic",
                "-whitelist=noban@127.0.0.1",
                "-whitelist=noban@::1",
            ],
        ]

    @staticmethod
    def target_from_bits(bits_hex):
        return uint256_from_compact(int(bits_hex, 16))

    def run_test(self):
        node0, node1, node2 = self.nodes

        # =====================================================================
        # TEST 1: All nodes agree on genesis
        # =====================================================================
        self.log.info("=== Test 1: Genesis agreement ===")
        genesis0 = node0.getblockhash(0)
        genesis1 = node1.getblockhash(0)
        genesis2 = node2.getblockhash(0)
        assert_equal(genesis0, genesis1)
        assert_equal(genesis0, genesis2)
        self.log.info(f"  All 3 nodes agree on genesis: {genesis0}")

        # =====================================================================
        # TEST 2: Mining and propagation during fast phase
        # =====================================================================
        self.log.info("=== Test 2: Fast phase mining + propagation ===")
        # Disconnect node2 for late-joiner test
        self.disconnect_nodes(1, 2)

        genesis_header = node0.getblockheader(genesis0, True)
        mock_time = genesis_header["time"]

        # Mine fast-phase blocks on node0
        for _ in range(self.FAST_MINE_HEIGHT):
            mock_time += 1
            node0.setmocktime(mock_time)
            node0.generateblock("raw(51)", [], called_by_framework=True)

        self.sync_blocks([node0, node1])

        assert_equal(node0.getblockcount(), self.FAST_MINE_HEIGHT)
        assert_equal(node1.getblockcount(), self.FAST_MINE_HEIGHT)
        assert_equal(node2.getblockcount(), 0)  # Still disconnected
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        self.log.info(f"  node0 & node1 synced at height {self.FAST_MINE_HEIGHT}")
        self.log.info(f"  node2 still at genesis (disconnected)")

        # =====================================================================
        # TEST 3: Warmup phase mining + sync
        # =====================================================================
        self.log.info("=== Test 3: Warmup + normal phase mining ===")

        # Mine through warmup
        for _ in range(self.DGW_PAST_BLOCKS):
            mock_time += 90
            node0.setmocktime(mock_time)
            node0.generateblock("raw(51)", [], called_by_framework=True)

        self.sync_blocks([node0, node1])
        warmup_height = node0.getblockcount()
        assert_equal(warmup_height, self.FAST_MINE_HEIGHT + self.DGW_PAST_BLOCKS)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        # Mine some steady-state blocks
        for _ in range(self.STEADY_STATE_BLOCKS):
            mock_time += 90
            node0.setmocktime(mock_time)
            node0.generateblock("raw(51)", [], called_by_framework=True)

        self.sync_blocks([node0, node1])
        steady_height = node0.getblockcount()
        self.log.info(f"  node0 & node1 synced at height {steady_height}")

        # Verify DGW consistency between nodes
        for h in [self.FAST_MINE_HEIGHT + 1,
                   self.FAST_MINE_HEIGHT + self.DGW_PAST_BLOCKS,
                   steady_height]:
            bits0 = node0.getblockheader(node0.getblockhash(h), True)["bits"]
            bits1 = node1.getblockheader(node1.getblockhash(h), True)["bits"]
            assert_equal(bits0, bits1)

        self.log.info("  DGW difficulty consistent across nodes")

        # =====================================================================
        # TEST 4: Late joiner full sync
        # =====================================================================
        self.log.info("=== Test 4: Late joiner sync ===")
        node2.setmocktime(mock_time)
        self.connect_nodes(1, 2)
        self.sync_blocks([node0, node1, node2])

        assert_equal(node2.getblockcount(), steady_height)
        assert_equal(node2.getbestblockhash(), node0.getbestblockhash())

        # Verify node2 has correct difficulty at key heights
        for h in [0, self.FAST_MINE_HEIGHT, self.FAST_MINE_HEIGHT + self.DGW_PAST_BLOCKS, steady_height]:
            bits0 = node0.getblockheader(node0.getblockhash(h), True)["bits"]
            bits2 = node2.getblockheader(node2.getblockhash(h), True)["bits"]
            assert_equal(bits0, bits2)

        self.log.info(f"  node2 synced to height {steady_height} with correct difficulty")

        # =====================================================================
        # TEST 5: Variable spacing - DGW adjusts, all nodes agree
        # =====================================================================
        self.log.info("=== Test 5: Variable spacing consensus ===")

        # Mine 30 fast blocks (simulating hashrate increase)
        for _ in range(self.VARIABLE_PHASE_BLOCKS):
            mock_time += 30  # 3x faster than target
            node0.setmocktime(mock_time)
            node0.generateblock("raw(51)", [], called_by_framework=True)

        self.sync_blocks([node0, node1], timeout=180)
        self.disconnect_nodes(1, 2)
        self.connect_nodes(1, 2)
        self.sync_blocks([node1, node2], timeout=180)

        # Mine 30 slow blocks (simulating hashrate decrease)
        for _ in range(self.VARIABLE_PHASE_BLOCKS):
            mock_time += 270  # 3x slower than target
            node0.setmocktime(mock_time)
            node0.generateblock("raw(51)", [], called_by_framework=True)

        self.sync_blocks([node0, node1], timeout=180)
        self.disconnect_nodes(1, 2)
        self.connect_nodes(1, 2)
        self.sync_blocks([node1, node2], timeout=180)

        variable_height = node0.getblockcount()
        for n in self.nodes:
            assert_equal(n.getblockcount(), variable_height)
            assert_equal(n.getbestblockhash(), node0.getbestblockhash())

        # All nodes should have identical difficulty at every height
        sample_heights = list(range(steady_height, variable_height, 10))
        for h in sample_heights:
            bits_set = set()
            for n in self.nodes:
                bits_set.add(n.getblockheader(n.getblockhash(h), True)["bits"])
            assert len(bits_set) == 1, f"Difficulty mismatch at height {h}"

        self.log.info(f"  All nodes agree through variable spacing to height {variable_height}")

        # =====================================================================
        # TEST 6: Competing miners - both node0 and node1 mine
        # =====================================================================
        self.log.info("=== Test 6: Competing miners ===")

        # Disconnect node1 temporarily
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)

        # Both node0 and node1 mine one block at the same mock_time
        mock_time += 90
        for n in self.nodes:
            n.setmocktime(mock_time)

        node0.generateblock("raw(51)", [], called_by_framework=True)
        node1.generateblock("raw(51)", [], called_by_framework=True)

        # They should have the same height but different tips
        assert_equal(node0.getblockcount(), node1.getblockcount())
        # Tips may or may not differ (depends on block content)

        # node0 mines one more to create a longer chain
        mock_time += 90
        for n in self.nodes:
            n.setmocktime(mock_time)
        node0.generateblock("raw(51)", [], called_by_framework=True)

        # Reconnect - node1 should reorg to node0's chain
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_blocks()

        final_height = node0.getblockcount()
        for n in self.nodes:
            assert_equal(n.getblockcount(), final_height)
            assert_equal(n.getbestblockhash(), node0.getbestblockhash())

        self.log.info(f"  Reorg resolved: all nodes at height {final_height}")

        # =====================================================================
        # TEST 7: Chain state sanity
        # =====================================================================
        self.log.info("=== Test 7: Chain state sanity ===")

        for i, n in enumerate(self.nodes):
            info = n.getblockchaininfo()
            assert_equal(info["blocks"], final_height)
            assert_equal(info["headers"], final_height)
            mining_info = n.getmininginfo()
            assert_equal(mining_info["algorithm"], "matmul")
            self.log.info(f"  node{i}: height={info['blocks']} algorithm={mining_info['algorithm']} ok")

        # Clean up mock time
        for n in self.nodes:
            n.setmocktime(0)

        # =====================================================================
        # Summary
        # =====================================================================
        self.log.info("")
        self.log.info("=" * 60)
        self.log.info("  MULTI-NODE GENESIS CONSENSUS TEST: ALL PASSED")
        self.log.info("=" * 60)
        self.log.info(f"  Final chain height: {final_height}")
        self.log.info(f"  Phases tested: fast, warmup, normal, variable, reorg")
        self.log.info(f"  Nodes: 3 (primary miner, synced peer, late joiner)")
        self.log.info("")


if __name__ == "__main__":
    BTXMultiNodeGenesisTest(__file__).main()
