#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Exercise parallel and serial block-input prevout fetching."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class PrevoutFetchTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-prevoutfetchthreads=8"],
            ["-prevoutfetchthreads=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        parallel_node, serial_node = self.nodes

        self.log.info("Restart parallel node and verify its worker pool starts")
        with parallel_node.assert_debug_log(
            expected_msgs=["Block input prevout fetching uses 8 additional threads"],
        ):
            self.restart_node(0, extra_args=["-prevoutfetchthreads=8"])
        # Make the serial node the outbound peer so it will download blocks
        # from the restarted parallel node while in IBD.
        self.connect_nodes(1, 0)

        parallel_node.createwallet(wallet_name="parallel")
        serial_node.createwallet(wallet_name="serial")
        parallel_wallet = parallel_node.get_wallet_rpc("parallel")
        serial_wallet = serial_node.get_wallet_rpc("serial")

        self.log.info("Mine spendable P2MR outputs on both validation modes")
        mine_address = parallel_wallet.getnewaddress(address_type="p2mr")
        self.generatetoaddress(parallel_node, 101, mine_address)

        self.log.info("Connect a block containing an external prevout on both modes")
        receive_address = serial_wallet.getnewaddress(address_type="p2mr")
        txid = parallel_wallet.sendtoaddress(receive_address, Decimal("1"))
        block_hash = self.generatetoaddress(parallel_node, 1, mine_address, sync_fun=self.no_op)[0]
        self.sync_blocks()
        assert_equal(parallel_node.getbestblockhash(), block_hash)
        assert_equal(serial_node.getbestblockhash(), block_hash)
        assert txid in parallel_node.getblock(block_hash)["tx"]

        self.log.info("Reject a negative thread count")
        self.stop_node(1)
        serial_node.assert_start_raises_init_error(
            extra_args=["-prevoutfetchthreads=-1"],
            expected_msg=r"-prevoutfetchthreads must be non-negative",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Cap an excessive thread count at 16")
        with serial_node.assert_debug_log(
            expected_msgs=["Block input prevout fetching uses 16 additional threads"],
        ):
            self.start_node(1, extra_args=["-prevoutfetchthreads=100"])


if __name__ == "__main__":
    PrevoutFetchTest(__file__).main()
