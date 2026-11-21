#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet load on startup.

Verify that a bitcoind node can maintain list of wallets loading on startup
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)


class WalletStartupTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        self.start_nodes()

    def test_disabled_settings(self, node):
        self.log.info("Test wallet startup preferences with dynamic settings disabled")
        load_message = "Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."

        settings_path = node.chain_path / "settings.json"
        settings_before = settings_path.read_bytes()
        self.restart_node(0, extra_args=["-nosettings"])
        assert_equal(node.listwallets(), [''])

        # TestNode.createwallet() always sends passphrase='', which adds an "Empty string given as
        # passphrase" warning; send only the arguments this check is about.
        assert_equal(node.createwallet_passthrough(wallet_name="no_settings", load_on_startup=True), {"name": "no_settings", "warnings": [load_message]})
        assert_equal(set(node.listwallets()), {'', 'no_settings'})

        # Leaving the startup preference unchanged does not warn, and the wallet remains usable.
        assert_equal(node.unloadwallet(wallet_name="no_settings"), {})
        assert_equal(node.loadwallet(filename="no_settings"), {"name": "no_settings"})
        assert_equal(node.get_wallet_rpc("no_settings").getwalletinfo()["walletname"], "no_settings")

        assert_equal(node.loadwallet(filename="w2", load_on_startup=True), {"name": "w2", "warnings": [load_message]})
        assert_equal(set(node.listwallets()), {'', 'no_settings', 'w2'})

        assert_equal(node.unloadwallet(wallet_name="no_settings", load_on_startup=False), {"warnings": ["Wallet load on startup setting could not be updated, so wallet may still be loaded next node startup."]})
        assert_equal(set(node.listwallets()), {'', 'w2'})
        self.stop_node(0)
        assert_equal(settings_path.read_bytes(), settings_before)

        # Re-enabling settings restores the original startup preferences.
        self.start_node(0)
        assert_equal(set(node.listwallets()), {'w2', 'w3'})

    def run_test(self):
        self.log.info('Should start without any wallets')
        assert_equal(self.nodes[0].listwallets(), [])
        assert_equal(self.nodes[0].listwalletdir(), {'wallets': []})

        self.log.info('New default wallet should load by default when there are no other wallets')
        self.nodes[0].createwallet(wallet_name='', load_on_startup=False)
        self.restart_node(0)
        assert_equal(self.nodes[0].listwallets(), [''])

        self.log.info('Test load on startup behavior')
        self.nodes[0].createwallet(wallet_name='w0', load_on_startup=True)
        self.nodes[0].createwallet(wallet_name='w1', load_on_startup=False)
        self.nodes[0].createwallet(wallet_name='w2', load_on_startup=True)
        self.nodes[0].createwallet(wallet_name='w3', load_on_startup=False)
        self.nodes[0].createwallet(wallet_name='w4', load_on_startup=False)
        self.nodes[0].unloadwallet(wallet_name='w0', load_on_startup=False)
        self.nodes[0].unloadwallet(wallet_name='w4', load_on_startup=False)
        self.nodes[0].loadwallet(filename='w4', load_on_startup=True)
        assert_equal(set(self.nodes[0].listwallets()), set(('', 'w1', 'w2', 'w3', 'w4')))
        self.restart_node(0)
        assert_equal(set(self.nodes[0].listwallets()), set(('', 'w2', 'w4')))
        self.nodes[0].unloadwallet(wallet_name='', load_on_startup=False)
        self.nodes[0].unloadwallet(wallet_name='w4', load_on_startup=False)
        self.nodes[0].loadwallet(filename='w3', load_on_startup=True)
        self.nodes[0].loadwallet(filename='')
        self.restart_node(0)
        assert_equal(set(self.nodes[0].listwallets()), set(('w2', 'w3')))

        self.test_disabled_settings(self.nodes[0])

if __name__ == '__main__':
    WalletStartupTest(__file__).main()
