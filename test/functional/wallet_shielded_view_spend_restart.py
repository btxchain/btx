#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""z_viewtransaction after a restart for a spend this wallet did not create.

Wallet a2 is a restored backup of wallet a, so it holds the same keys. Wallet a
spends its only note to wallet c with no change. For a2 that transaction is not
a wallet transaction, and its block holds no note of a2: the note a2 knows was
confirmed in an earlier block. z_viewtransaction must still show the spend
after a restart, as it does before one.
"""
from decimal import Decimal

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletShieldedViewSpendRestartTest(BitcoinTestFramework):
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
        for name in ("d", "a", "c"):
            node.createwallet(wallet_name=name, descriptors=True)
        d = encrypt_and_unlock_wallet(node, "d")
        a = encrypt_and_unlock_wallet(node, "a")
        c = encrypt_and_unlock_wallet(node, "c")

        self.log.info("Wallet d mines and seeds the ring; wallet a gets one 2 BTX note")
        mine_addr = d.getnewaddress()
        fund_trusted_transparent_balance(self, node, d, mine_addr, Decimal("10.0"), sync_fun=self.no_op)
        ensure_ring_diversity(self, node, d, mine_addr, d.z_getnewaddress())
        d.sendtoaddress(a.getnewaddress(), Decimal("3.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        a.z_shieldfunds(Decimal("2.0"), a.z_getnewaddress())
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(int(a.z_getbalance()["note_count"]), 1)

        self.log.info("Wallet a2 is a restored backup of a")
        backup = node.datadir_path / "a.bak"
        a.backupwallet(backup)
        node.restorewallet("a2", backup)
        a2 = node.get_wallet_rpc("a2")
        a2.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        assert_equal(int(a2.z_getbalance()["note_count"]), 1)

        self.log.info("Wallet a spends the note to c with no change")
        spend = a.z_sendtoaddress(c.z_getnewaddress(), Decimal("2.0"), "", "", True)
        txid = spend["txid"] if isinstance(spend, dict) else spend
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(Decimal(a2.z_getbalance()["balance"]), Decimal("0"))
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", a2.gettransaction, txid)

        def spends_ours(view):
            return [s for s in view["spends"] if s.get("is_ours")]

        before = a2.z_viewtransaction(txid)
        assert_equal(len(spends_ours(before)), 1)
        assert not [o for o in before["outputs"] if o.get("is_ours")]

        self.log.info("Restart: a2 must still show its spend")
        self.restart_node(0)
        node = self.nodes[0]
        for name in ("d", "a", "c", "a2"):
            if name not in node.listwallets():
                node.loadwallet(name)
        a2 = node.get_wallet_rpc("a2")
        a2.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", a2.gettransaction, txid)
        after = a2.z_viewtransaction(txid)
        assert_equal(spends_ours(after), spends_ours(before))
        assert_equal(after["family"], before["family"])


if __name__ == "__main__":
    WalletShieldedViewSpendRestartTest(__file__).main()
