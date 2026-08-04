#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test upgrading pre-existing legacy wallets without creating one in btxd."""

import shutil

from test_framework.bdb import dump_bdb_kv
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_is_hex_string,
)


class UpgradeWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.wallet_names = []
        self.extra_args = [
            ["-nowallet"],
            ["-usehd=1", "-keypool=2"],
            ["-usehd=0", "-keypool=2"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_bdb()
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(
            self.num_nodes,
            extra_args=self.extra_args,
            versions=[None, 160300, 150200],
        )
        self.start_nodes()

    @staticmethod
    def assert_upgrade(wallet, previous_version, requested_version=None, expected_version=None):
        new_version = expected_version if expected_version is not None else requested_version
        assert_equal(wallet.getwalletinfo()["walletversion"], previous_version)
        result = wallet.upgradewallet(requested_version)
        assert_equal(result["previous_version"], previous_version)
        assert_equal(result["current_version"], new_version)
        assert "Wallet upgraded successfully" in result["result"]
        assert_equal(wallet.getwalletinfo()["walletversion"], new_version)

    def copy_and_load(self, source, wallet_name):
        target = self.nodes[0].wallets_path / wallet_name
        target.mkdir(parents=True)
        shutil.copyfile(source, target / "wallet.dat")
        self.nodes[0].loadwallet(wallet_name)
        return self.nodes[0].get_wallet_rpc(wallet_name), target / "wallet.dat"

    def run_test(self):
        current, v16, v15 = self.nodes

        v16_wallet = v16.get_wallet_rpc("wallet.dat")
        v15_wallet = v15.get_wallet_rpc("wallet.dat")
        assert_equal(v16_wallet.getwalletinfo()["walletversion"], 159900)
        assert_equal(v15_wallet.getwalletinfo()["walletversion"], 60000)
        v16_wallet.unloadwallet()
        self.stop_node(1)
        self.stop_node(2)

        self.log.info("Upgrade a v0.16.3 HD wallet in the current loader")
        v16_source = v16.wallets_path / "wallet.dat"
        upgraded_v16, v16_file = self.copy_and_load(v16_source, "upgrade_v16")
        before = dump_bdb_kv(v16_file)
        self.assert_upgrade(upgraded_v16, previous_version=159900, expected_version=169900)
        after = dump_bdb_kv(v16_file)
        assert len(after) >= len(before)
        assert b"\x07hdchain" in after
        upgraded_v16.unloadwallet()

        self.log.info("Upgrade a v0.15.2 non-HD wallet to split-HD support")
        v15_source = v15.chain_path / "wallet.dat"
        upgraded_v15, v15_file = self.copy_and_load(v15_source, "upgrade_v15")
        assert b"\x07hdchain" not in dump_bdb_kv(v15_file)
        self.assert_upgrade(upgraded_v15, previous_version=60000, requested_version=169900)
        info = upgraded_v15.getwalletinfo()
        assert_is_hex_string(info["hdseedid"])
        upgraded_records = dump_bdb_kv(v15_file)
        assert b"\x07hdchain" in upgraded_records

        self.log.info("Reject downgrade requests without mutating the wallet")
        error = upgraded_v15.upgradewallet(40000)
        assert_equal(error["previous_version"], 169900)
        assert_equal(error["current_version"], 169900)
        assert "Cannot downgrade wallet" in error["error"]
        assert_equal(upgraded_v15.getwalletinfo()["walletversion"], 169900)
        upgraded_v15.unloadwallet()

        if self.is_sqlite_compiled():
            self.log.info("Descriptor wallets remain a successful no-op")
            current.createwallet(wallet_name="desc_upgrade", descriptors=True)
            descriptor_wallet = current.get_wallet_rpc("desc_upgrade")
            result = descriptor_wallet.upgradewallet()
            assert_equal(result["previous_version"], result["current_version"])
            assert_equal(result["result"], "Already at latest version. Wallet version unchanged.")


if __name__ == '__main__':
    UpgradeWalletTest(__file__).main()
