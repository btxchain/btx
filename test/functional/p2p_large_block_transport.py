#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Verify P2P relay and sync of blocks larger than 4 MB."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import create_lots_of_big_transactions
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    gen_return_txouts,
)
from test_framework.wallet import MiniWallet


class P2PLargeBlockTransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.rpc_timeout = 180

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def run_test(self):
        node0, node1 = self.nodes

        self.log.info("Raise mining policy to consensus maximum so large serialized blocks can be assembled")
        self.restart_node(0, extra_args=["-blockmaxweight=24000000", "-acceptnonstdtxn=1"])
        self.connect_nodes(0, 1)

        wallet = MiniWallet(node0)
        self.generate(wallet, 260, sync_fun=self.no_op)
        wallet.rescan_utxos()

        fee = Decimal(str(node0.getnetworkinfo()["relayfee"])) * Decimal(100)
        txouts = gen_return_txouts()
        target_mempool_bytes = 5_000_000
        for _ in range(8):
            if node0.getmempoolinfo()["bytes"] > target_mempool_bytes:
                break
            create_lots_of_big_transactions(wallet, node0, fee, tx_batch_size=20, txouts=txouts)

        mempool_bytes = node0.getmempoolinfo()["bytes"]
        assert_greater_than(mempool_bytes, target_mempool_bytes)

        large_block_hash = self.generate(node0, 1, sync_fun=self.no_op)[0]
        block_size = len(node0.getblock(large_block_hash, 0)) // 2
        assert_greater_than(block_size, 4_000_000)
        assert_greater_than(24_000_000, block_size)

        self.log.info(f"Waiting for P2P sync of {block_size}-byte block")
        self.sync_blocks(timeout=240)
        assert_equal(node1.getbestblockhash(), large_block_hash)

        peer_block_size = len(node1.getblock(large_block_hash, 0)) // 2
        assert_greater_than(peer_block_size, 4_000_000)


if __name__ == "__main__":
    P2PLargeBlockTransportTest(__file__).main()
