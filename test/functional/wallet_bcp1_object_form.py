#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the object forms of the BCP/1 package RPC arguments.

createexchangebatch and prepareexternalsign take the withdrawal outputs as an
array or as {"outputs"|"recipients": [...]}, optionally with change_address in
the same object. finalizeexternalsign takes the package itself or
{"package": ..., "signatures": [...]}. Each object form must give the same
recipients (or the same result) as the plain form, and the node must stay up.
Unlike feature_bcp1.py this needs no external signer, so it runs everywhere.
createexchangebatch and createconsolidationtx also take lock_unspents: left
false, two batches may share an input; set true, they must not.
"""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY, REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BCP1ObjectFormTest(BitcoinTestFramework):
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
        self.generatetoaddress(node, COINBASE_MATURITY + 3, node.getnewaddress(address_type="p2mr"))
        a, b, change = (node.getnewaddress(address_type="p2mr") for _ in range(3))
        outs = [{"address": a, "amount": Decimal("0.2")}, {"address": b, "amount": Decimal("0.3")}]
        outs_amount_first = [{"amount": o["amount"], "address": o["address"]} for o in outs]

        def atoms(sent):
            return sorted((o["address"], int(o["amount"] * COIN)) for o in sent)

        def recipients(package):
            return sorted((o["address"], o["amount_atoms"]) for o in package["outputs"] if o["address"] != change)

        batch = node.createexchangebatch(outs, {"change_address": change})
        assert_equal(recipients(batch), atoms(outs))

        forms = [
            ({"recipients": outs[:1]}, outs[:1]),
            ({"outputs": outs}, outs),
            ({"recipients": outs}, outs),
            ({"outputs": outs, "change_address": change}, outs),
            ({"change_address": change, "recipients": outs}, outs),
            ({"recipients": outs_amount_first, "change_address": change}, outs),
        ]
        for form, sent in forms:
            for rpc in ("createexchangebatch", "prepareexternalsign"):
                self.log.info(f"{rpc} with {len(sent)} output(s) in an object of keys {list(form)}")
                package = getattr(node, rpc)(form, {"change_address": change})
                assert_equal(recipients(package), atoms(sent))

        self.log.info("finalizeexternalsign with {package: ...}")
        assert_equal(node.finalizeexternalsign({"package": batch}), node.finalizeexternalsign(batch))

        self.log.info("amount_atoms outside MoneyRange is refused as amount is")
        too_big = [[{"address": a, "amount_atoms": 2**63 - 1}],
                   [{"address": a, "amount_atoms": 2**62}, {"address": b, "amount_atoms": 2**62}],
                   [{"address": a, "amount_atoms": 21_000_000 * COIN + 1}],
                   [{"address": a, "amount_atoms": -1}]]
        for outs_bad in too_big:
            assert_raises_rpc_error(-3, "Amount out of range", node.createexchangebatch, outs_bad, {"change_address": change})
            assert_raises_rpc_error(-3, "Amount out of range", node.prepareexternalsign, {"recipients": outs_bad}, {"change_address": change})
        assert_equal(recipients(node.createexchangebatch(outs, {"change_address": change})), atoms(outs))

        def selected(package):
            return sorted((u["txid"], u["vout"]) for u in package["selected_utxos"])

        def locked():
            return {(e["txid"], e["vout"]) for e in node.listlockunspent()}

        pay = [{"address": a, "amount": Decimal("0.1")}]
        self.log.info("lockUnspents is rejected and a fee ceiling locks nothing")
        assert_equal(node.listlockunspent(), [])
        assert_raises_rpc_error(-8, "Use lock_unspents instead of lockUnspents",
                                node.createexchangebatch, pay, {"change_address": change, "lockUnspents": True})
        assert_raises_rpc_error(-8, "Use lock_unspents instead of lockUnspents",
                                node.createconsolidationtx, {"change_address": change, "lockUnspents": True})
        assert_raises_rpc_error(-4, "estimated fee exceeds fee_ceiling",
                                node.createexchangebatch, pay,
                                {"change_address": change, "lock_unspents": True, "fee_ceiling": Decimal("0.00000001")})
        assert_raises_rpc_error(-4, "estimated fee exceeds fee_ceiling",
                                node.createconsolidationtx,
                                {"change_address": change, "lock_unspents": True, "fee_ceiling": Decimal("0.00000001")})
        assert_equal(node.listlockunspent(), [])

        utxos = node.listunspent()
        assert len(utxos) >= 2
        keep = max(utxos, key=lambda u: u["amount"])
        keep_out = (keep["txid"], keep["vout"])
        others = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos if (u["txid"], u["vout"]) != keep_out]
        node.lockunspent(False, others)
        self.log.info("two batches with lock_unspents false may share an input")
        shared = node.createexchangebatch(pay, {"change_address": change})
        shared_again = node.createexchangebatch(pay, {"change_address": change, "lock_unspents": False})
        assert_equal(selected(shared), [keep_out])
        assert_equal(selected(shared_again), [keep_out])
        cons = node.createconsolidationtx({"change_address": change, "max_inputs": 1})
        cons_again = node.createconsolidationtx({"change_address": change, "max_inputs": 1, "lock_unspents": False})
        assert_equal(selected(cons), [keep_out])
        assert_equal(selected(cons_again), [keep_out])
        assert keep_out not in locked()
        node.lockunspent(True)
        assert_equal(node.listlockunspent(), [])

        self.log.info("two batches with lock_unspents true must not share an input")
        locked_a = node.createexchangebatch(pay, {"change_address": change, "lock_unspents": True})
        locked_b = node.createexchangebatch(pay, {"change_address": change, "lock_unspents": True})
        assert set(selected(locked_a)).isdisjoint(selected(locked_b))
        assert set(selected(locked_a)).issubset(locked())
        assert set(selected(locked_b)).issubset(locked())
        node.lockunspent(True)
        cons_a = node.createconsolidationtx({"change_address": change, "max_inputs": 1, "lock_unspents": True})
        cons_b = node.createconsolidationtx({"change_address": change, "max_inputs": 1, "lock_unspents": True})
        assert set(selected(cons_a)).isdisjoint(selected(cons_b))
        assert set(selected(cons_a)).issubset(locked())
        assert set(selected(cons_b)).issubset(locked())


if __name__ == '__main__':
    BCP1ObjectFormTest(__file__).main()
