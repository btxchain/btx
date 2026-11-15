#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test lock_unspents on createexchangebatch and createconsolidationtx.

Until a BCP/1 package is broadcast, the next package can select the same
inputs (#514). With lock_unspents the inputs of each package are locked in
memory, as walletcreatefundedpsbt does with lockUnspents: a wallet with six
3 BTX coins then builds six 2 BTX batches on six different coins and refuses a
seventh. Without the option nothing is locked, as before.
"""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY, REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def inputs(package):
    return [(u["txid"], u["vout"]) for u in package["selected_utxos"]]


class BCP1LockUnspentsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-fallbackfee=0.0002", "-modelnet=0"] + REGTEST_GENERIC_P2P_MATMUL_ARGS]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.generatetoaddress(node, COINBASE_MATURITY + 3, miner.getnewaddress(address_type="p2mr"))
        node.createwallet("venue")
        venue = node.get_wallet_rpc("venue")
        miner.sendmany("", {venue.getnewaddress(address_type="p2mr"): 3 for _ in range(6)})
        self.generatetoaddress(node, 1, miner.getnewaddress(address_type="p2mr"))
        assert_equal(len(venue.listunspent()), 6)
        change = venue.getnewaddress(address_type="p2mr")
        out = [{"address": miner.getnewaddress(address_type="p2mr"), "amount": Decimal("2")}]

        def locked():
            return sorted((u["txid"], u["vout"]) for u in venue.listlockunspent())

        self.log.info("Without lock_unspents a batch locks nothing (unchanged default)")
        venue.createexchangebatch(out, {"change_address": change})
        venue.createexchangebatch(out, {"change_address": change, "lock_unspents": False})
        assert_equal(locked(), [])

        self.log.info("Six batches with lock_unspents select six different coins and lock them")
        batches = [venue.createexchangebatch(out, {"change_address": change, "lock_unspents": True}) for _ in range(6)]
        used = [i for b in batches for i in inputs(b)]
        assert_equal(len(used), 6)
        assert_equal(len(set(used)), 6)
        assert_equal(locked(), sorted(used))

        self.log.info("A seventh batch finds no unlocked coin")
        assert_raises_rpc_error(-4, "Insufficient funds", venue.createexchangebatch, out, {"change_address": change, "lock_unspents": True})

        self.log.info("lockunspent true on a dropped batch's selected_utxos frees its coin for the next batch")
        dropped = inputs(batches[1])
        venue.lockunspent(True, [{"txid": t, "vout": v} for t, v in dropped])
        again = venue.createexchangebatch(out, {"change_address": change, "lock_unspents": True})
        assert_equal(inputs(again), dropped)
        venue.lockunspent(True)

        self.log.info("A refused batch (fee_ceiling) locks nothing")
        assert_raises_rpc_error(-4, "fee_ceiling", venue.createexchangebatch, out,
                                {"change_address": change, "fee_ceiling": Decimal("0.00000001"), "lock_unspents": True})
        assert_equal(locked(), [])

        self.log.info("lock_unspents must be a bool")
        assert_raises_rpc_error(-3, "expected type bool", venue.createexchangebatch, out, {"change_address": change, "lock_unspents": 1})
        assert_equal(locked(), [])

        self.log.info("estimateconsolidationfee locks nothing; createconsolidationtx with lock_unspents locks its inputs")
        venue.estimateconsolidationfee({"change_address": change, "lock_unspents": True})
        assert_equal(locked(), [])
        venue.createconsolidationtx(change)
        assert_equal(locked(), [])
        sweep = venue.createconsolidationtx(change, {"lock_unspents": True})
        assert_equal(len(inputs(sweep)), 6)
        assert_equal(locked(), sorted(inputs(sweep)))
        assert_raises_rpc_error(-6, "no deposit UTXOs", venue.createconsolidationtx, change, {"lock_unspents": True})
        assert_raises_rpc_error(-4, "Insufficient funds", venue.createexchangebatch, out, {"change_address": change})


if __name__ == '__main__':
    BCP1LockUnspentsTest(__file__).main()
