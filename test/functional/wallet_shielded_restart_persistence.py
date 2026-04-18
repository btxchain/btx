#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletShieldedRestartPersistenceTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]
        # Native v2_send proof generation exceeds the default RPC client timeout.
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")

        self.log.info("Create confirmed shielded balance")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("10.0"), sync_fun=self.no_op
        )
        zaddr = wallet.z_getnewaddress()
        wallet.z_shieldfunds(Decimal("2.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, wallet, mine_addr, zaddr)
        balance_before = Decimal(wallet.z_getbalance()["balance"])
        assert balance_before > Decimal("0")

        self.log.info("Restart node and reload wallet; shielded balance and spendability must persist")
        self.restart_node(0)
        node = self.nodes[0]
        if "shielded" not in node.listwallets():
            node.loadwallet("shielded")
        wallet = node.get_wallet_rpc("shielded")
        wallet.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        balance_after = Decimal(wallet.z_getbalance()["balance"])
        assert_equal(balance_after, balance_before)

        zdest = wallet.z_getnewaddress()
        send_res = wallet.z_sendmany([{"address": zdest, "amount": Decimal("0.1")}])
        assert send_res["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Restart with full VerifyDB (-checklevel=4 -checkblocks=0)")
        self.restart_node(0, extra_args=["-checklevel=4", "-checkblocks=0"])
        node = self.nodes[0]
        if "shielded" not in node.listwallets():
            node.loadwallet("shielded")
        wallet = node.get_wallet_rpc("shielded")
        wallet.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        balance_post_verifydb = Decimal(wallet.z_getbalance()["balance"])
        assert balance_post_verifydb > Decimal("0")

        zdest_post_verifydb = wallet.z_getnewaddress()
        send_post_verifydb = wallet.z_sendmany([{"address": zdest_post_verifydb, "amount": Decimal("0.05")}])
        assert send_post_verifydb["txid"] in node.getrawmempool()


if __name__ == "__main__":
    WalletShieldedRestartPersistenceTest(__file__).main()
