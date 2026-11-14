#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Issued shielded addresses survive a gap search after bundle restore."""

from decimal import Decimal

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletShieldedRehydrateIssuedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0", "-regtestshieldedmatrictdisableheight=500"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="payer", descriptors=True)
        payer = encrypt_and_unlock_wallet(node, "payer")
        mine_addr = payer.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, payer, mine_addr, Decimal("20.0"), sync_fun=self.no_op
        )
        ensure_ring_diversity(self, node, payer, mine_addr, payer.z_getnewaddress())

        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        self.log.info("Hand out three shielded addresses and pay the first and the third")
        addrs = [wallet.z_getnewaddress() for _ in range(3)]
        assert_equal(len(set(addrs)), 3)
        payer.z_shieldfunds(Decimal("1.0"), addrs[0])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        payer.z_shieldfunds(Decimal("0.4"), addrs[2])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        before = wallet.z_getbalance()
        assert_equal(before["note_count"], 2)
        assert_equal(Decimal(before["balance"]), Decimal("1.4"))

        self.log.info("Restore the seed bundle and unlock; both payments must be visible")
        bundle_path = node.datadir_path / "issued.btxwallet.json"
        exported = wallet.exportwalletbundle(str(bundle_path), None, 1)
        assert_equal(exported["success"], True)
        restored = node.restorewalletbundle(
            "restored",
            str(bundle_path),
            None,
            False,
            SHIELDED_WALLET_PASSPHRASE,
        )
        assert_equal(restored["success"], True)
        restored_wallet = node.get_wallet_rpc("restored")
        restored_wallet.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        after = restored_wallet.z_getbalance()
        assert_equal(after["note_count"], 2)
        assert_equal(Decimal(after["balance"]), Decimal("1.4"))

        self.log.info("An encrypted wallet with no shielded address searches the empty gap once")
        node.createwallet(wallet_name="emptygap", descriptors=True)
        empty = node.get_wallet_rpc("emptygap")
        empty.encryptwallet(SHIELDED_WALLET_PASSPHRASE)
        empty = node.get_wallet_rpc("emptygap")
        log_pos = node.debug_log_size(encoding="utf-8")
        with node.assert_debug_log(["re-derived"]):
            empty.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 120)
        empty.walletlock()
        with node.assert_debug_log([], unexpected_msgs=["re-derived"]):
            empty.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 120)
        with open(node.debug_log_path, encoding="utf-8", errors="replace") as log_file:
            log_file.seek(log_pos)
            chunk = log_file.read()
        assert_equal(chunk.count("re-derived"), 1)


if __name__ == "__main__":
    WalletShieldedRehydrateIssuedTest(__file__).main()
