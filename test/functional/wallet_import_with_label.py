#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that importprivkey/importaddress refuse classical secp ingest."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import (
    create_legacy_wallet_with_tool,
    get_generate_key,
)

IMPORTPRIVKEY_DISABLED_ERROR = (
    "BTX PQ policy: importprivkey is disabled (legacy ECDSA); use importdescriptors with P2MR"
)
IMPORTADDRESS_SECP_DISABLED_ERROR = (
    "BTX PQ policy: importaddress is disabled for secp256k1; use importdescriptors with P2MR"
)


class ImportWithLabel(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            self.skip_if_no_wallet()
        self.enable_wallet_if_possible()
        if not self.is_bdb_compiled():
            self.skip_if_no_sqlite()
        self.skip_if_no_wallet_tool()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=[["-nowallet"]] * self.num_nodes)
        for node in self.nodes:
            create_legacy_wallet_with_tool(self, node, self.default_wallet_name)
        self.start_nodes()
        for node in self.nodes:
            node.loadwallet(self.default_wallet_name)

    def run_test(self):
        key = get_generate_key()
        self.log.info("importaddress refuses secp256k1 P2PKH ingest")
        assert_raises_rpc_error(
            -8,
            IMPORTADDRESS_SECP_DISABLED_ERROR,
            self.nodes[1].importaddress,
            key.p2pkh_addr,
            "Test Label",
        )
        self.log.info("importprivkey is disabled (legacy ECDSA)")
        assert_raises_rpc_error(
            -8,
            IMPORTPRIVKEY_DISABLED_ERROR,
            self.nodes[1].importprivkey,
            key.privkey,
        )


if __name__ == '__main__':
    ImportWithLabel(__file__).main()
