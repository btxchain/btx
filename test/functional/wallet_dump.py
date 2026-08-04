#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test legacy dump/import compatibility without creating legacy wallets in btxd."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import (
    WalletUnlock,
    create_legacy_wallet_with_tool,
    get_generate_key,
)


class WalletDumpTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            self.skip_if_no_wallet()
        self.enable_wallet_if_possible()
        if not self.is_bdb_compiled():
            self.skip_if_no_sqlite()
        self.skip_if_no_wallet_tool()

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=[["-nowallet"]])
        create_legacy_wallet_with_tool(self, self.nodes[0], "dump")
        self.start_nodes()
        self.nodes[0].loadwallet("dump")

    def create_legacy_wallet(self, wallet_name):
        self.stop_node(0)
        create_legacy_wallet_with_tool(self, self.nodes[0], wallet_name)
        self.start_node(0)
        self.nodes[0].loadwallet(wallet_name)

    def run_test(self):
        # BTX intentionally forbids newly generated legacy destinations and
        # transactions. Keep this test on the supported compatibility surface:
        # load an existing wallet and round-trip pre-existing key material.
        key = get_generate_key()
        self.nodes[0].importprivkey(key.privkey, "runtime fixture", False)
        assert self.nodes[0].getaddressinfo(key.p2pkh_addr)["ismine"]

        wallet_unenc_dump = self.nodes[0].datadir_path / "wallet.unencrypted.dump"
        wallet_enc_dump = self.nodes[0].datadir_path / "wallet.encrypted.dump"

        result = self.nodes[0].dumpwallet(wallet_unenc_dump)
        assert result["filename"] == str(wallet_unenc_dump)
        with open(wallet_unenc_dump, encoding="utf8") as dump_file:
            dump_text = dump_file.read()
        assert "# End of dump" in dump_text
        assert key.p2pkh_addr in dump_text

        self.nodes[0].encryptwallet("test")
        with WalletUnlock(self.nodes[0], "test"):
            self.nodes[0].dumpwallet(wallet_enc_dump)
            assert_raises_rpc_error(-8, "already exists", lambda: self.nodes[0].dumpwallet(wallet_enc_dump))

        self.create_legacy_wallet("w2")
        w2 = self.nodes[0].get_wallet_rpc("w2")
        assert not w2.getaddressinfo(key.p2pkh_addr)["ismine"]
        w2.importwallet(wallet_unenc_dump)
        assert w2.getaddressinfo(key.p2pkh_addr)["ismine"]

        w2.unloadwallet()
        self.nodes[0].loadwallet("w2")
        assert self.nodes[0].get_wallet_rpc("w2").getaddressinfo(key.p2pkh_addr)["ismine"]


if __name__ == '__main__':
    WalletDumpTest(__file__).main()
