#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Outputs to the change branch of a BCP/1 deposit pool count as change.

importdepositpool labels a change-branch entry <account>/change/<index>
(older imports: change/<index>). Those addresses take the venue's own change
and consolidation outputs; they are not customer deposit addresses. The
wallet's change rule (an output with no address-book entry) never matches a
labelled pool entry, so listdepositutxos listed them as deposits even without
include_change, with is_change false.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBCP1PoolChangeBranchTest(BitcoinTestFramework):
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
        node.createwallet("miner")
        miner = node.get_wallet_rpc("miner")
        node.createwallet("source")
        self.source = node.get_wallet_rpc("source")
        self.generatetoaddress(node, 110, miner.getnewaddress(), sync_fun=self.no_op)

        node.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        venue = node.get_wallet_rpc("venue")
        deposit_pk, deposit = self.key()
        account_deposit_pk, account_deposit = self.key()
        change_pk, change = self.key()
        legacy_change_pk, legacy_change = self.key()
        custom_pk, custom = self.key()
        venue.importdepositpool([
            {"pubkey": deposit_pk, "index": 0},
            {"pubkey": account_deposit_pk, "index": 0, "account": 3},
            {"pubkey": change_pk, "index": 0, "branch": 1},
            {"pubkey": legacy_change_pk, "label": "change/1"},
            {"pubkey": custom_pk, "label": "cold change"},
        ])
        for address in [deposit, account_deposit, change, legacy_change, custom]:
            miner.sendtoaddress(address, Decimal("2"))
        self.generatetoaddress(node, 1, miner.getnewaddress(), sync_fun=self.no_op)

        self.log.info("listdepositutxos leaves the change branch out unless include_change is set")
        deposits = {u["address"]: u for u in venue.listdepositutxos()}
        assert_equal(sorted(deposits), sorted([deposit, account_deposit, custom]))
        everything = {u["address"]: u for u in venue.listdepositutxos({"include_change": True})}
        assert_equal(sorted(everything), sorted([deposit, account_deposit, change, legacy_change, custom]))

        self.log.info("is_change names the change branch, and only it")
        for address in [change, legacy_change]:
            assert_equal(everything[address]["is_change"], True)
        for address in [deposit, account_deposit, custom]:
            assert_equal(everything[address]["is_change"], False)


if __name__ == '__main__':
    WalletBCP1PoolChangeBranchTest(__file__).main()
