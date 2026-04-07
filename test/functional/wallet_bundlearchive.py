#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise backupwalletbundlearchive and restorewalletbundlearchive."""

from decimal import Decimal
from pathlib import Path

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBundleArchiveTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 120
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")

        self.log.info("Archive backup and restore help surfaces should render without internal schema errors")
        assert "include_viewing_keys" in wallet.help("backupwalletbundlearchive")
        assert "bundled_manifest" in node.help("restorewalletbundlearchive")

        self.log.info("Create confirmed shielded balance")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("1.0"), sync_fun=self.no_op
        )
        available_balance = Decimal(wallet.getbalance())
        assert available_balance > Decimal("0.01")
        shield_amount = min(available_balance / 2, Decimal("1.0"))
        zaddr = wallet.z_getnewaddress()
        wallet.z_shieldfunds(shield_amount, zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, wallet, mine_addr, zaddr)
        shielded_balance = Decimal(wallet.z_getbalance()["balance"])
        assert shielded_balance > Decimal("0")

        self.log.info("Lock the encrypted wallet")
        wallet.walletlock()

        archive_path = node.datadir_path / "shielded.bundle.btx"
        assert_raises_rpc_error(
            -13,
            "provide the passphrase to backupwalletbundlearchive",
            wallet.backupwalletbundlearchive,
            archive_path,
            "archive-pass",
        )

        self.log.info("Export the archive through btx-cli with hidden wallet and archive passphrases")
        archive = node.cli(
            "-rpcwallet=shielded",
            "-stdinwalletpassphrase",
            "-stdinbundlepassphrase",
            input="pass\narchive-pass\n",
        ).backupwalletbundlearchive(archive_path)
        assert_equal(archive["unlocked_by_rpc"], True)
        assert_equal(archive["integrity"]["integrity_ok"], True)
        assert_equal(archive["warnings"], [])

        archive_file = Path(archive["archive_file"])
        assert archive_file.is_file()
        assert_equal(archive["bundle_name"], "shielded.bundle")
        assert "manifest.json" in archive["bundle_files"]
        assert "getbalances.json" in archive["bundle_files"]
        assert "shielded.backup.dat" in archive["bundle_files"]

        self.log.info("The source wallet should be relocked after archive export")
        assert_raises_rpc_error(
            -13,
            "walletpassphrase first",
            wallet.listdescriptors,
            True,
        )

        self.log.info("Wrong archive passphrase should fail the restore")
        assert_raises_rpc_error(
            -14,
            "archive passphrase entered was incorrect",
            node.restorewalletbundlearchive,
            "broken-restore",
            archive_file,
            "wrong-pass",
        )

        self.log.info("Restore from the encrypted archive through btx-cli")
        restore = node.cli("-stdinbundlepassphrase", input="archive-pass\n").restorewalletbundlearchive(
            "restored",
            archive_file,
        )
        assert_equal(restore["name"], "restored")
        assert_equal(restore["bundle_name"], "shielded.bundle")
        assert_equal(restore["bundled_manifest"]["integrity_ok"], True)
        assert_equal(restore["bundled_manifest"]["integrity_warnings"], [])
        assert_equal(restore["bundled_integrity"]["integrity_ok"], True)

        restored = node.get_wallet_rpc("restored")
        restored.walletpassphrase("pass", 120)
        assert_equal(Decimal(restored.z_getbalance()["balance"]), shielded_balance)


if __name__ == "__main__":
    WalletBundleArchiveTest(__file__).main()
