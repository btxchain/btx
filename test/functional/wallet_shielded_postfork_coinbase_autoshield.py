#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


DISABLE_HEIGHT = 5


class WalletShieldedPostForkCoinbaseAutoshieldTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-regtestshieldedmatrictdisableheight={DISABLE_HEIGHT}",
        ]]
        self.rpc_timeout = 1200

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")

        mine_addr = wallet.getnewaddress()
        self.log.info("Mine past maturity with autoshield enabled so post-fork coinbase rewards become compatible inputs")
        self.generatetoaddress(node, 102, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 102)

        self.log.info("Wait for the default autoshield path to enqueue a mature-coinbase shielding transaction")
        self.wait_until(lambda: len(node.getrawmempool()) >= 1, timeout=120)
        txid = node.getrawmempool()[0]
        tx_view = wallet.z_viewtransaction(txid)
        assert_equal(tx_view["family"], "shielded_v2")

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        balance = wallet.z_getbalance()
        assert_greater_than(Decimal(str(balance["balance"])), Decimal("0"))
        assert int(balance["note_count"]) >= 1


if __name__ == "__main__":
    WalletShieldedPostForkCoinbaseAutoshieldTest(__file__).main()
