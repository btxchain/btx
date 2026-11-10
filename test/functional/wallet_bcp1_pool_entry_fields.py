#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""importdepositpool reads index, branch and account as deriveexchangeaddress does.

An indexed pool entry gets the label <account>/<deposit|change>/<index>, and
deriveexchangeaddress finds pool entries by that label. A branch, index or
account that deriveexchangeaddress would refuse must be refused at import
time, not filed under a label nobody looks up (or under the deposit branch),
and a refused pool must not leave the entries before the bad one imported.
"""
from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

NO_ENTRY = "No imported pool entry for that index"


class WalletBCP1PoolEntryFieldsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self):
        pubkey = self.source.getaddressinfo(self.source.getnewaddress())["pubkey"]
        address = self.nodes[0].deriveaddresses(f"mr({pubkey})", None, {"require_checksum": False})[0]
        return pubkey, address

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("source")
        self.source = node.get_wallet_rpc("source")
        node.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        venue = node.get_wallet_rpc("venue")

        self.log.info("Entries deriveexchangeaddress would refuse are refused at import")
        pubkey, _ = self.key()
        for fields, message in [
            ({"index": 3, "branch": "1"}, "branch must be an integer from 0 to 1"),
            ({"index": 3, "branch": 2}, "branch must be an integer from 0 to 1"),
            ({"index": -1}, "index must be an integer from 0 to 4294967295"),
            ({"index": 4294967296}, "index must be an integer from 0 to 4294967295"),
            ({"index": "07"}, "index must be an integer from 0 to 4294967295"),
            ({"index": 3, "account": -1}, "account must be an integer from 0 to 4294967295"),
        ]:
            assert_raises_rpc_error(-4, message, venue.importdepositpool, [{"pubkey": pubkey, **fields}])
        assert_equal(venue.listlabels(), [])

        self.log.info("A refused pool imports none of its entries")
        good_pubkey, _ = self.key()
        assert_raises_rpc_error(-4, "Deposit pool item 1: branch must be an integer from 0 to 1",
                                venue.importdepositpool,
                                [{"pubkey": good_pubkey, "index": 5}, {"pubkey": pubkey, "index": 6, "branch": "1"}])
        assert_raises_rpc_error(-4, NO_ENTRY, venue.deriveexchangeaddress, 5)
        assert_equal(venue.listlabels(), [])

        self.log.info("Valid entries land where deriveexchangeaddress looks for them")
        change_pubkey, change_address = self.key()
        deposit_pubkey, deposit_address = self.key()
        account_pubkey, account_address = self.key()
        result = venue.importdepositpool([
            {"pubkey": change_pubkey, "index": 3, "branch": 1},
            {"pubkey": deposit_pubkey, "index": 4, "branch": 0},
            {"pubkey": account_pubkey, "index": 2, "account": 7},
        ])
        assert_equal(result["imported"], 3)
        assert_equal(sorted(venue.listlabels()), ["0/change/3", "0/deposit/4", "7/deposit/2"])
        assert_equal(venue.deriveexchangeaddress(3, {"branch": 1})["address"], change_address)
        assert_raises_rpc_error(-4, NO_ENTRY, venue.deriveexchangeaddress, 3)
        assert_equal(venue.deriveexchangeaddress(4)["address"], deposit_address)
        assert_equal(venue.deriveexchangeaddress(2, {"account": 7})["address"], account_address)


if __name__ == '__main__':
    WalletBCP1PoolEntryFieldsTest(__file__).main()
