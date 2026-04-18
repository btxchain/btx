#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise backupwalletbundle on an encrypted shielded wallet."""

from decimal import Decimal
import json
from pathlib import Path

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBackupBundleTest(BitcoinTestFramework):
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

        self.log.info("Backup bundle help surfaces should render without internal schema errors")
        help_text = wallet.help("backupwalletbundle")
        assert "include_viewing_keys" in help_text
        assert "integrity" in help_text

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

        locked_bundle_dir = node.datadir_path / "locked-bundle"
        assert_raises_rpc_error(
            -13,
            "provide the passphrase to backupwalletbundle",
            wallet.backupwalletbundle,
            locked_bundle_dir,
        )

        self.log.info("Export the bundle through btx-cli with -stdinwalletpassphrase")
        bundle_dir = node.datadir_path / "shielded.bundle"
        bundle = node.cli("-rpcwallet=shielded", "-stdinwalletpassphrase", input="pass\n").backupwalletbundle(bundle_dir)
        assert_equal(bundle["unlocked_by_rpc"], True)
        assert_equal(bundle["integrity"]["integrity_ok"], True)
        assert_equal(bundle["warnings"], [])

        bundle_path = Path(bundle["bundle_dir"])
        backup_path = Path(bundle["backup_file"])
        assert bundle_path.is_dir()
        assert backup_path.is_file()
        assert (bundle_path / "manifest.json").is_file()
        assert (bundle_path / "z_verifywalletintegrity.json").is_file()
        assert (bundle_path / "getbalances.json").is_file()
        assert (bundle_path / "listdescriptors_private.json").is_file()
        assert (bundle_path / "shielded_viewing_keys" / "index.tsv").is_file()
        manifest = json.loads((bundle_path / "manifest.json").read_text(encoding="utf-8"))
        assert_equal(manifest["integrity_ok"], True)
        assert_equal(manifest["integrity_warnings"], [])

        self.log.info("The source wallet should be relocked after the bundle export")
        assert_raises_rpc_error(
            -13,
            "walletpassphrase first",
            wallet.listdescriptors,
            True,
        )

        self.log.info("Restore from the bundled backup.dat and verify the encrypted wallet round-trip")
        restore_res = node.restorewallet("restored", backup_path)
        assert_equal(restore_res["name"], "restored")
        assert any("Unlock it after restore" in warning for warning in restore_res["warnings"])
        restored = node.get_wallet_rpc("restored")
        restored.walletpassphrase("pass", 120)

        restored_integrity = restored.z_verifywalletintegrity()
        assert_equal(restored_integrity["integrity_ok"], True)
        assert_equal(Decimal(restored.z_getbalance()["balance"]), shielded_balance)


if __name__ == "__main__":
    WalletBackupBundleTest(__file__).main()
