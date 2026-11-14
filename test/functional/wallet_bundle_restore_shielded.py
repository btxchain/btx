#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shielded funds after restorewalletbundle into an encrypted wallet (#664).

Wallet orig makes five shielded addresses and receives one note on the
second. Its exported bundle is restored as an encrypted wallet. After the
first walletpassphrase, the restored wallet must see that note without a
z_getnewaddress or a rescan first.
"""
from decimal import Decimal

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBundleRestoreShieldedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0", "-regtestshieldedmatrictdisableheight=500"]]
        # Native v2_send proof generation exceeds the default RPC client timeout.
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="d", descriptors=True)
        d = encrypt_and_unlock_wallet(node, "d")
        mine_addr = d.getnewaddress()
        fund_trusted_transparent_balance(self, node, d, mine_addr, Decimal("10.0"), sync_fun=self.no_op)
        ensure_ring_diversity(self, node, d, mine_addr, d.z_getnewaddress())

        node.createwallet(wallet_name="orig", descriptors=True)
        orig = encrypt_and_unlock_wallet(node, "orig")
        addrs = [orig.z_getnewaddress() for _ in range(5)]
        d.z_shieldfunds(Decimal("1.0"), addrs[1])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(Decimal(orig.z_getbalance()["balance"]), Decimal("1.0"))

        self.log.info("Restore orig's bundle as an encrypted wallet; the first unlock finds the note")
        path = node.datadir_path / "orig.btxwallet.json"
        orig.exportwalletbundle(str(path), None, 1)
        node.restorewalletbundle("rest", str(path), None, True, SHIELDED_WALLET_PASSPHRASE)
        rest = node.get_wallet_rpc("rest")
        rest.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        assert_equal(Decimal(rest.z_getbalance()["balance"]), Decimal("1.0"))


if __name__ == "__main__":
    WalletBundleRestoreShieldedTest(__file__).main()
