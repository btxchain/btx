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


if __name__ == '__main__':
    BCP1ObjectFormTest(__file__).main()
