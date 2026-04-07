#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import encrypt_and_unlock_wallet, fund_trusted_transparent_balance
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


DISABLE_HEIGHT = 140


class WalletShieldedUnlockRehydrateAutoshieldTest(BitcoinTestFramework):
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

        self.log.info("Seed shielded state before restart so first unlock must rehydrate historical shielded data")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self,
            node,
            wallet,
            mine_addr,
            Decimal("2.0"),
            maturity_blocks=101,
            sync_fun=self.no_op,
        )
        if node.getrawmempool():
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        zaddr = wallet.z_getnewaddress()
        wallet.z_shieldfunds(Decimal("1.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])
        assert_greater_than(Decimal(wallet.z_getbalance()["balance"]), Decimal("0"))

        self.log.info("Accumulate mature transparent outputs while the wallet is locked so autoshield has work queued")
        wallet.walletlock()
        self.generatetoaddress(node, 140, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])

        self.log.info("After restart, first unlock should rehydrate state but stay side-effect free")
        self.restart_node(0)
        node = self.nodes[0]
        node.loadwallet("shielded")
        wallet = node.get_wallet_rpc("shielded")
        wallet.walletpassphrase("pass", 120)
        assert_equal(node.getrawmempool(), [])
        assert_greater_than(Decimal(wallet.z_getbalance()["balance"]), Decimal("0"))

        self.log.info("Coin locks must suppress background autoshielding")
        spendable = wallet.listunspent(1)
        assert spendable
        locked_outputs = [{"txid": coin["txid"], "vout": coin["vout"]} for coin in spendable]
        assert_equal(wallet.lockunspent(False, locked_outputs), True)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Once locks are released, the next block should enqueue the mature-coinbase autoshield transaction")
        assert_equal(wallet.lockunspent(True, locked_outputs), True)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        self.wait_until(lambda: len(node.getrawmempool()) >= 1, timeout=120)


if __name__ == "__main__":
    WalletShieldedUnlockRehydrateAutoshieldTest(__file__).main()
