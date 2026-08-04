#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test implicit-SegWit recovery for a pre-existing legacy keypool."""

import shutil
import time

from test_framework.address import (
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
)
from test_framework.blocktools import (
    REGTEST_GENERIC_P2P_MATMUL_ARGS,
    create_block,
    create_coinbase,
)
from test_framework.script_util import key_to_p2pkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import create_legacy_wallet_with_tool


class ImplicitSegwitTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.wallet_names = []
        self.extra_args = [
            ["-walletimplicitsegwit=1", "-nowallet", *REGTEST_GENERIC_P2P_MATMUL_ARGS],
            ["-walletimplicitsegwit=0", "-nowallet", *REGTEST_GENERIC_P2P_MATMUL_ARGS],
        ]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            self.skip_if_no_wallet()
        self.enable_wallet_if_possible()
        if not self.is_bdb_compiled():
            self.skip_if_no_sqlite()
        self.skip_if_no_wallet_tool()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        # Create one recovery fixture with implicit SegWit disabled, then give
        # both nodes the exact same pre-existing keypool. The runtime flag is
        # therefore the only difference when a recovered keypool entry is used.
        self.keypool_pubkeys = create_legacy_wallet_with_tool(
            self,
            self.nodes[0],
            self.default_wallet_name,
        )
        assert len(self.keypool_pubkeys) > 5
        self.nodes[1].wallets_path.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            self.nodes[0].wallets_path / "wallet.dat",
            self.nodes[1].wallets_path / "wallet.dat",
        )
        self.start_nodes()
        for node in self.nodes:
            node.loadwallet(self.default_wallet_name)
        self.connect_nodes(1, 0)

    def run_test(self):
        self.log.info("Load the same recovered legacy keypool under both settings")
        for node in self.nodes:
            assert not node.getwalletinfo()["descriptors"]
            assert_raises_rpc_error(-4, "no available keys", node.getnewaddress)

        self.log.info("Use a restored keypool entry and compare learned related scripts")
        pubkey = bytes.fromhex(self.keypool_pubkeys[5])
        p2pkh = key_to_p2pkh(pubkey)
        p2wpkh = key_to_p2wpkh(pubkey)
        p2sh_p2wpkh = key_to_p2sh_p2wpkh(pubkey)

        tip = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())
        coinbase = create_coinbase(
            tip["height"] + 1,
            script_pubkey=key_to_p2pkh_script(pubkey),
        )
        block = create_block(int(tip["hash"], 16), coinbase, max(tip["time"] + 1, int(time.time())))
        block.solve()
        block_hex = block.serialize().hex()
        self.nodes[0].submitblock(block_hex)
        self.nodes[1].submitblock(block_hex)
        self.sync_blocks()
        for node in self.nodes:
            node.syncwithvalidationinterfacequeue()

        for node in self.nodes:
            assert node.getaddressinfo(p2pkh)["ismine"]
        assert self.nodes[0].getaddressinfo(p2wpkh)["ismine"]
        assert self.nodes[0].getaddressinfo(p2sh_p2wpkh)["ismine"]
        assert not self.nodes[1].getaddressinfo(p2wpkh)["ismine"]
        assert not self.nodes[1].getaddressinfo(p2sh_p2wpkh)["ismine"]

        self.log.info("Recovered implicit-script ownership survives restart")
        self.restart_node(0)
        self.restart_node(1)
        self.nodes[0].loadwallet(self.default_wallet_name)
        self.nodes[1].loadwallet(self.default_wallet_name)
        assert self.nodes[0].getaddressinfo(p2wpkh)["ismine"]
        assert self.nodes[0].getaddressinfo(p2sh_p2wpkh)["ismine"]
        assert not self.nodes[1].getaddressinfo(p2wpkh)["ismine"]
        assert not self.nodes[1].getaddressinfo(p2sh_p2wpkh)["ismine"]


if __name__ == '__main__':
    ImplicitSegwitTest(__file__).main()
