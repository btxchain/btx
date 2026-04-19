#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test external signer.

Verify that a bitcoind node can use an external signer command
See also rpc_signer.py for tests without wallet context.
"""
import os
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletSignerTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def mock_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'signer.py')
        return sys.executable + " " + path

    def mock_no_connected_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'no_signer.py')
        return sys.executable + " " + path

    def mock_invalid_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'invalid_signer.py')
        return sys.executable + " " + path

    def mock_multi_signers_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'multi_signers.py')
        return sys.executable + " " + path

    def set_test_params(self):
        self.num_nodes = 2

        self.extra_args = [
            [],
            [f"-signer={self.mock_signer_path()}", '-keypool=10'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def set_mock_result(self, node, res):
        with open(os.path.join(node.cwd, "mock_result"), "w", encoding="utf8") as f:
            f.write(res)

    def clear_mock_result(self, node):
        os.remove(os.path.join(node.cwd, "mock_result"))

    def run_test(self):
        self.test_valid_signer()
        self.test_disconnected_signer()
        self.restart_node(1, [f"-signer={self.mock_invalid_signer_path()}", "-keypool=10"])
        self.test_invalid_signer()
        self.restart_node(1, [f"-signer={self.mock_multi_signers_path()}", "-keypool=10"])
        self.test_multiple_signers()

    def test_valid_signer(self):
        self.log.debug(f"-signer={self.mock_signer_path()}")

        # Create new wallets for an external signer.
        # disable_private_keys and descriptors must be true:
        assert_raises_rpc_error(-4, "Private keys must be disabled when using an external signer", self.nodes[1].createwallet, wallet_name='not_hww', disable_private_keys=False, descriptors=True, external_signer=True)
        assert_raises_rpc_error(
            -8,
            "only descriptor wallets are supported (descriptors=true)",
            self.nodes[1].createwallet,
            wallet_name='not_hww',
            disable_private_keys=True,
            descriptors=False,
            external_signer=True,
        )

        self.nodes[1].createwallet(wallet_name='hww', disable_private_keys=True, descriptors=True, external_signer=True)
        hww = self.nodes[1].get_wallet_rpc('hww')
        assert_equal(hww.getwalletinfo()["external_signer"], True)

        # Flag can't be set afterwards (could be added later for non-blank descriptor based watch-only wallets)
        self.nodes[1].createwallet(wallet_name='not_hww', disable_private_keys=True, descriptors=True, external_signer=False)
        not_hww = self.nodes[1].get_wallet_rpc('not_hww')
        assert_equal(not_hww.getwalletinfo()["external_signer"], False)

        # Flag can be set
        not_hww.setwalletflag("external_signer", True)
        assert_equal(not_hww.getwalletinfo()["external_signer"], True)

        # Flag can be unset
        not_hww.setwalletflag("external_signer", False)
        assert_equal(not_hww.getwalletinfo()["external_signer"], False)

        # assert_raises_rpc_error(-4, "Multiple signers found, please specify which to use", wallet_name='not_hww', disable_private_keys=True, descriptors=True, external_signer=True)

        self.log.info('Verify imported descriptors are ranged P2MR/BIP87h based')
        descs = hww.listdescriptors(private=False)["descriptors"]
        active = [d["desc"] for d in descs if d.get("active")]
        assert_equal(len(active), 2)
        for desc in active:
            assert "mr(" in desc
            assert "pk_slh(" in desc
            assert "/87h/" in desc
            assert "/*" in desc

        self.log.info('Verify external signer exposes a usable ranged keypool for P2MR')
        address_0 = hww.getnewaddress(address_type="p2mr")
        address_1 = hww.getnewaddress(address_type="p2mr")
        assert address_0 != address_1

    def test_disconnected_signer(self):
        self.log.info('Test disconnected external signer')

        # First create a wallet with the signer connected
        self.nodes[1].createwallet(wallet_name='hww_disconnect', disable_private_keys=True, external_signer=True)
        hww = self.nodes[1].get_wallet_rpc('hww_disconnect')
        assert_equal(hww.getwalletinfo()["external_signer"], True)

        # Obtain receive and change addresses while signer is connected.
        funding_address = hww.getnewaddress(address_type="p2mr")
        change_address = hww.getrawchangeaddress(address_type="p2mr")
        self.nodes[0].sendtoaddress(funding_address, 1)
        self.generate(self.nodes[0], 1)

        # Restart node with no signer connected
        self.log.debug(f"-signer={self.mock_no_connected_signer_path()}")
        self.restart_node(1, [f"-signer={self.mock_no_connected_signer_path()}", "-keypool=10"])
        self.nodes[1].loadwallet('hww_disconnect')
        hww = self.nodes[1].get_wallet_rpc('hww_disconnect')

        # Try to spend
        dest = self.nodes[0].getnewaddress(address_type="p2mr")
        assert_raises_rpc_error(
            -25,
            "External signer not found",
            hww.send,
            outputs=[{dest: 0.5}],
            options={"change_address": change_address},
        )

    def test_invalid_signer(self):
        self.log.debug(f"-signer={self.mock_invalid_signer_path()}")
        self.log.info('Test invalid external signer')
        assert_raises_rpc_error(-1, "Invalid descriptor", self.nodes[1].createwallet, wallet_name='hww_invalid', disable_private_keys=True, descriptors=True, external_signer=True)

    def test_multiple_signers(self):
        self.log.debug(f"-signer={self.mock_multi_signers_path()}")
        self.log.info('Test multiple external signers')

        assert_raises_rpc_error(-1, "More than one external signer found", self.nodes[1].createwallet, wallet_name='multi_hww', disable_private_keys=True, descriptors=True, external_signer=True)

        self.log.info('Test selecting a signer by fingerprint')
        self.restart_node(1, [f"-signer={self.mock_multi_signers_path()}", "-signerfingerprint=00000002", "-keypool=10"])
        self.nodes[1].createwallet(wallet_name='multi_hww_selected', disable_private_keys=True, descriptors=True, external_signer=True)
        selected = self.nodes[1].get_wallet_rpc('multi_hww_selected')
        assert_equal(selected.getwalletinfo()["external_signer"], True)
        active_descs = [d for d in selected.listdescriptors(private=False)["descriptors"] if d.get("active")]
        assert_equal(len(active_descs), 2)

if __name__ == '__main__':
    WalletSignerTest(__file__).main()
