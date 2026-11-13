#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A watch-only deposit pool sweeps and takes change to its own omnibus address.

createconsolidationtx without a change address, and createexchangebatch on a
watch-only wallet, pick the omnibus address from the pool labels: change 0 of
account 0, else deposit 0. importdepositpool labels indexed entries
<account>/<deposit|change>/<index>; the legacy labels change/<index> and
deposit/<index> keep working. A pool without either label must ask for a
change address instead of using some other address-book entry.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBCP1OmnibusChangeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def pool_keys(self, count):
        """Single-leaf mr(<ML-DSA-44>) pool keys, ordered by scriptPubKey (address-book order)."""
        node = self.nodes[0]
        keys = []
        for _ in range(count):
            pubkey = self.source.getaddressinfo(self.source.getnewaddress())["pubkey"]
            address = node.deriveaddresses(f"mr({pubkey})", None, {"require_checksum": False})[0]
            keys.append((node.validateaddress(address)["scriptPubKey"], pubkey, address))
        keys.sort()
        return [(pubkey, address) for _spk, pubkey, address in keys]

    def venue(self, name, entries, deposits):
        node = self.nodes[0]
        node.createwallet(wallet_name=name, disable_private_keys=True, blank=True)
        wallet = node.get_wallet_rpc(name)
        assert_equal(wallet.importdepositpool(entries)["success"], True)
        for address in deposits:
            self.miner.sendtoaddress(address, Decimal("2"))
        self.generatetoaddress(node, 1, self.miner.getnewaddress())
        return wallet

    def outputs(self, package):
        tx = self.nodes[0].decodepsbt(package["psbt"])["tx"]
        return [vout["scriptPubKey"]["address"] for vout in tx["vout"]]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        self.miner = node.get_wallet_rpc("miner")
        node.createwallet("source")
        self.source = node.get_wallet_rpc("source")
        self.generatetoaddress(node, 110, self.miner.getnewaddress())
        payee = self.miner.getnewaddress()

        self.log.info("Indexed labels: the sweep and the batch change go to 0/change/0")
        keys = self.pool_keys(6)
        change_pk, change = keys[-1]  # sorts last in the address book
        deposits = keys[:-1]
        entries = [{"pubkey": change_pk, "index": 0, "branch": 1}]
        entries += [{"pubkey": pk, "index": i} for i, (pk, _a) in enumerate(deposits)]
        wallet = self.venue("indexed", entries, [a for _pk, a in deposits])
        assert_equal(wallet.getaddressinfo(change)["labels"], ["0/change/0"])
        assert_equal(self.outputs(wallet.createconsolidationtx({"min_confirmations": 1})), [change])
        assert_equal(sorted(self.outputs(wallet.createexchangebatch([{"address": payee, "amount": 1}]))),
                     sorted([payee, change]))

        self.log.info("Without a change entry the sweep goes to 0/deposit/0")
        keys = self.pool_keys(4)
        deposit0_pk, deposit0 = keys[-1]
        others = keys[:-1]
        entries = [{"pubkey": deposit0_pk, "index": 0}]
        entries += [{"pubkey": pk, "index": i + 1} for i, (pk, _a) in enumerate(others)]
        wallet = self.venue("indexed_no_change", entries, [a for _pk, a in others])
        assert_equal(wallet.getaddressinfo(deposit0)["labels"], ["0/deposit/0"])
        assert_equal(self.outputs(wallet.createconsolidationtx({"min_confirmations": 1})), [deposit0])

        self.log.info("Legacy labels still pick change/0")
        keys = self.pool_keys(4)
        legacy_pk, legacy_change = keys[-1]
        entries = [{"pubkey": legacy_pk, "label": "change/0"}]
        entries += [{"pubkey": pk, "label": f"deposit/{i}"} for i, (pk, _a) in enumerate(keys[:-1])]
        wallet = self.venue("legacy", entries, [a for _pk, a in keys[:-1]])
        assert_equal(self.outputs(wallet.createconsolidationtx({"min_confirmations": 1})), [legacy_change])

        self.log.info("A pool without either label asks for a change address")
        keys = self.pool_keys(3)
        entries = [{"pubkey": pk, "label": f"customer-{i}"} for i, (pk, _a) in enumerate(keys)]
        wallet = self.venue("custom", entries, [a for _pk, a in keys])
        assert_raises_rpc_error(-8, "change_address required", wallet.createconsolidationtx, {"min_confirmations": 1})
        sweep = keys[0][1]
        assert_equal(self.outputs(wallet.createconsolidationtx({"min_confirmations": 1, "change_address": sweep})), [sweep])


if __name__ == "__main__":
    WalletBCP1OmnibusChangeTest(__file__).main()
