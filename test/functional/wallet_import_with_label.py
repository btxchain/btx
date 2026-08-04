#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the behavior of RPC importprivkey on set and unset labels of
addresses.

It tests different cases in which an address is imported with importaddress
with or without a label and then its private key is imported with importprivkey
with and without a label.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet_util import (
    create_legacy_wallet_with_tool,
    get_generate_key,
    test_address,
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
        """Main test logic"""

        self.log.info(
            "Test importaddress with label and importprivkey without label."
        )
        self.log.info("Import a watch-only address with a label.")
        key = get_generate_key()
        address = key.p2pkh_addr
        label = "Test Label"
        self.nodes[1].importaddress(address, label)
        test_address(self.nodes[1],
                     address,
                     iswatchonly=True,
                     ismine=False,
                     labels=[label])

        self.log.info(
            "Import the watch-only address's private key without a "
            "label and the address should keep its label."
        )
        self.nodes[1].importprivkey(key.privkey)
        test_address(self.nodes[1], address, labels=[label])

        self.log.info(
            "Test importaddress without label and importprivkey with label."
        )
        self.log.info("Import a watch-only address without a label.")
        key2 = get_generate_key()
        address2 = key2.p2pkh_addr
        self.nodes[1].importaddress(address2)
        test_address(self.nodes[1],
                     address2,
                     iswatchonly=True,
                     ismine=False,
                     labels=[""])

        self.log.info(
            "Import the watch-only address's private key with a "
            "label and the address should have its label updated."
        )
        label2 = "Test Label 2"
        self.nodes[1].importprivkey(key2.privkey, label2)

        test_address(self.nodes[1], address2, labels=[label2])

        self.log.info("Test importaddress with label and importprivkey with label.")
        self.log.info("Import a watch-only address with a label.")
        key3 = get_generate_key()
        address3 = key3.p2pkh_addr
        label3_addr = "Test Label 3 for importaddress"
        self.nodes[1].importaddress(address3, label3_addr)
        test_address(self.nodes[1],
                     address3,
                     iswatchonly=True,
                     ismine=False,
                     labels=[label3_addr])

        self.log.info(
            "Import the watch-only address's private key with a "
            "label and the address should have its label updated."
        )
        label3_priv = "Test Label 3 for importprivkey"
        self.nodes[1].importprivkey(key3.privkey, label3_priv)

        test_address(self.nodes[1], address3, labels=[label3_priv])

        self.log.info(
            "Test importprivkey won't label new dests with the same "
            "label as others labeled dests for the same key."
        )
        self.log.info("Import a watch-only p2sh-segwit address with a label.")
        key4 = get_generate_key()
        address4 = key4.p2sh_p2wpkh_addr
        label4_addr = "Test Label 4 for importaddress"
        self.nodes[1].importaddress(address4, label4_addr)
        test_address(self.nodes[1],
                     address4,
                     iswatchonly=True,
                     ismine=False,
                     labels=[label4_addr],
                     embedded=None)

        self.log.info(
            "Import the watch-only address's private key without a "
            "label and new destinations for the key should have an "
            "empty label while the 'old' destination should keep "
            "its label."
        )
        self.nodes[1].importprivkey(key4.privkey)
        embedded_addr = self.nodes[1].getaddressinfo(address4)['embedded']['address']

        test_address(self.nodes[1], embedded_addr, labels=[""])

        test_address(self.nodes[1], address4, labels=[label4_addr])

        self.stop_nodes()


if __name__ == "__main__":
    ImportWithLabel(__file__).main()
