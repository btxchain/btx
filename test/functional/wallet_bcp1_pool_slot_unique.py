#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""One address per BCP/1 deposit pool slot.

deriveexchangeaddress finds the address for (account, branch, index) by its
address-book label: <account>/<deposit|change>/<index>, or the legacy
deposit/<index> and change/<index>. When two addresses carried the label of
one slot, the address it returned depended on address-book order. So
importdepositpool refuses a second address for a slot, and
deriveexchangeaddress refuses to choose when two addresses already share one.
"""
from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

NO_ENTRY = "No imported pool entry for that index"


class WalletBCP1PoolSlotUniqueTest(BitcoinTestFramework):
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
        return pubkey, self.nodes[0].deriveaddresses(f"mr({pubkey})", None, {"require_checksum": False})[0]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("source")
        self.source = node.get_wallet_rpc("source")
        node.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        venue = node.get_wallet_rpc("venue")

        self.log.info("A second address for an imported slot is refused")
        first_pk, first = self.key()
        other_pk, other = self.key()
        venue.importdepositpool([{"pubkey": first_pk, "index": 3}])
        assert_raises_rpc_error(-4, "Deposit pool item 0: 0/deposit/3 is already imported for another address",
                                venue.importdepositpool, [{"pubkey": other_pk, "index": 3}])
        assert_equal(venue.getaddressinfo(other)["iswatchonly"] or venue.getaddressinfo(other)["ismine"], False)
        assert_equal(venue.deriveexchangeaddress(3)["address"], first)

        self.log.info("Importing the same address again is fine, and other slots are independent")
        assert_equal(venue.importdepositpool([{"pubkey": first_pk, "index": 3}])["success"], True)
        change_pk, change = self.key()
        venue.importdepositpool([{"pubkey": change_pk, "index": 3, "branch": 1}])
        assert_equal(venue.deriveexchangeaddress(3, {"branch": 1})["address"], change)
        assert_equal(venue.deriveexchangeaddress(3)["address"], first)

        self.log.info("Two addresses for one slot in one pool are refused, and nothing is imported")
        a_pk, _ = self.key()
        b_pk, _ = self.key()
        assert_raises_rpc_error(-4, "Deposit pool item 1: 0/deposit/4 is already imported for another address",
                                venue.importdepositpool, [{"pubkey": a_pk, "index": 4}, {"pubkey": b_pk, "index": 4}])
        assert_raises_rpc_error(-4, NO_ENTRY, venue.deriveexchangeaddress, 4)

        self.log.info("A legacy label and an indexed entry name the same slot")
        legacy_pk, legacy = self.key()
        venue.importdepositpool([{"pubkey": legacy_pk, "label": "deposit/6"}])
        new_pk, _ = self.key()
        assert_raises_rpc_error(-4, "Deposit pool item 0: 0/deposit/6 is already imported for another address",
                                venue.importdepositpool, [{"pubkey": new_pk, "index": 6}])
        assert_equal(venue.deriveexchangeaddress(6)["address"], legacy)

        self.log.info("deriveexchangeaddress refuses a slot two addresses already share")
        eight_pk, _ = self.key()
        venue.importdepositpool([{"pubkey": eight_pk, "index": 8}])
        extra_pk, extra = self.key()
        venue.importdepositpool([{"pubkey": extra_pk, "label": "spare"}])
        venue.setlabel(extra, "0/deposit/8")
        assert_raises_rpc_error(-4, "More than one pool entry is labelled for 0/deposit/8", venue.deriveexchangeaddress, 8)

        self.log.info("A slot label wins over the bcp1-deposit default label")
        node.createwallet(wallet_name="plain", disable_private_keys=True, blank=True)
        plain = node.get_wallet_rpc("plain")
        plain.importdepositpool([self.key()[1] for _ in range(4)])
        zero_pk, zero = self.key()
        plain.importdepositpool([{"pubkey": zero_pk, "index": 0}])
        assert_equal(plain.deriveexchangeaddress(0)["address"], zero)


if __name__ == '__main__':
    WalletBCP1PoolSlotUniqueTest(__file__).main()
