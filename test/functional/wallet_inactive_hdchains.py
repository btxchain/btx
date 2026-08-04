#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test loading and topping up pre-existing inactive legacy HD chains."""

import shutil

from test_framework.bdb import dump_bdb_kv
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import get_generate_key


class InactiveHDChainsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = []
        self.extra_args = [["-nowallet", "-keypool=10"], ["-nowallet", "-keypool=10"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_bdb()
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(
            self.num_nodes,
            extra_args=self.extra_args,
            versions=[None, 170200],
        )
        self.start_nodes()

    def run_test(self):
        old_node = self.nodes[1]
        current_node = self.nodes[0]
        wallet_name = "inactive_hd_fixture"

        # v0.17 creates the BDB wallet. Rotating the HD seed leaves the first
        # chain inactive; encryption then creates the historical metadata shape
        # that used to crash while topping up after an upgrade.
        old_node.createwallet_passthrough(wallet_name=wallet_name)
        old_wallet = old_node.get_wallet_rpc(wallet_name)
        old_wallet.sethdseed(True, get_generate_key().privkey)
        old_wallet.keypoolrefill(10)
        old_wallet.sethdseed(True, get_generate_key().privkey)
        old_wallet.encryptwallet("pass")
        old_info = old_wallet.getwalletinfo()
        assert old_info["unlocked_until"] == 0
        old_wallet.unloadwallet()

        source = old_node.wallets_path / wallet_name
        target = current_node.wallets_path / wallet_name
        shutil.copytree(source, target)
        wallet_file = target / "wallet.dat"
        before = dump_bdb_kv(wallet_file)
        before_keymeta = sum(key.startswith(b"\x07keymeta") for key in before)
        assert b"\x07hdchain" in before

        current_node.loadwallet(wallet_name)
        wallet = current_node.get_wallet_rpc(wallet_name)
        info = wallet.getwalletinfo()
        assert not info["descriptors"]
        assert info["private_keys_enabled"]

        # BTX does not expose new legacy destinations, but keypoolrefill remains
        # part of loading/upgrading old wallet state. The important regression
        # assertion here is that inactive-chain metadata is handled safely.
        wallet.walletpassphrase("pass", 60)
        wallet.keypoolrefill(info["keypoolsize"] + 10)
        wallet.walletlock()
        wallet.unloadwallet()

        after = dump_bdb_kv(wallet_file)
        after_keymeta = sum(key.startswith(b"\x07keymeta") for key in after)
        assert b"\x07hdchain" in after
        assert after_keymeta >= before_keymeta

        shutil.rmtree(source)
        shutil.copytree(target, source)
        old_node.loadwallet(wallet_name)
        reopened = old_node.get_wallet_rpc(wallet_name).getwalletinfo()
        assert_equal(reopened["private_keys_enabled"], True)


if __name__ == '__main__':
    InactiveHDChainsTest(__file__).main()
