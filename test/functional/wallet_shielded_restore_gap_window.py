#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shielded notes past the first 20 indices after restorewalletbundle.

After a restore, the first unlock derives the shielded keys again and scans
the chain. The search must go on while notes turn up near its end, so that
a note is found as long as it is within the gap limit (20) of the note before.

1. Notes at index 15 and 24: both must be found.
2. A wallet that made many shielded sends has its whole balance on a change
   index past 20. The restored wallet must show that balance.
"""
from decimal import Decimal

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

GAP_LIMIT = 20


class WalletShieldedRestoreGapWindowTest(BitcoinTestFramework):
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

    def restore(self, wallet, name):
        node = self.nodes[0]
        path = node.datadir_path / f"{name}.btxwallet.json"
        wallet.exportwalletbundle(str(path), None, 1)
        node.restorewalletbundle(name, str(path), None, True, SHIELDED_WALLET_PASSPHRASE)
        restored = node.get_wallet_rpc(name)
        restored.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        return restored

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="d", descriptors=True)
        d = encrypt_and_unlock_wallet(node, "d")
        mine_addr = d.getnewaddress()
        fund_trusted_transparent_balance(self, node, d, mine_addr, Decimal("10.0"), sync_fun=self.no_op)
        d_zaddr = d.z_getnewaddress()
        ensure_ring_diversity(self, node, d, mine_addr, d_zaddr)

        self.log.info("Notes at index 15 and 24 are both found after a restore")
        node.createwallet(wallet_name="orig", descriptors=True)
        orig = encrypt_and_unlock_wallet(node, "orig")
        addrs = [orig.z_getnewaddress() for _ in range(25)]
        d.z_shieldfunds(Decimal("0.5"), addrs[15])
        d.z_shieldfunds(Decimal("0.5"), addrs[24])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(Decimal(orig.z_getbalance()["balance"]), Decimal("1.0"))
        rest = self.restore(orig, "rest")
        assert_equal(Decimal(rest.z_getbalance()["balance"]), Decimal("1.0"))

        self.log.info("After many sends, the restored wallet shows the balance on the last change index")
        node.createwallet(wallet_name="sender", descriptors=True)
        sender = encrypt_and_unlock_wallet(node, "sender")
        d.z_shieldfunds(Decimal("1.0"), sender.z_getnewaddress())
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        sends = 0
        while len(sender.z_listaddresses()) <= GAP_LIMIT + 2:
            assert sends < 40
            sender.z_sendmany([{"address": d_zaddr, "amount": Decimal("0.01")}])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
            sends += 1
        balance = Decimal(sender.z_getbalance()["balance"])
        assert_greater_than(balance, Decimal("0"))
        self.log.info(f"{sends} sends, {len(sender.z_listaddresses())} shielded addresses, balance {balance}")
        rest2 = self.restore(sender, "rest2")
        assert_equal(Decimal(rest2.z_getbalance()["balance"]), balance)


if __name__ == "__main__":
    WalletShieldedRestoreGapWindowTest(__file__).main()
