#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BCP/1 consolidation RPCs plan, price and spend the inputs they are given.

planconsolidation, estimateconsolidationfee and createconsolidationtx take
named inputs ("inputs" / "selected_utxos", directly or through a "plan" from
planconsolidation). Those inputs must be the ones planned, priced and spent.
"""

from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def outpoints(items):
    return sorted((i["txid"], i["vout"]) for i in items)


class WalletBcp1PlanInputsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-fallbackfee=0.0002", "-nomodelnet"] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.generatetoaddress(node, 110, wallet.getnewaddress(), sync_fun=self.no_op)
        for _ in range(4):
            wallet.sendtoaddress(wallet.getnewaddress(), Decimal("1.25"))
        self.generatetoaddress(node, 1, wallet.getnewaddress(), sync_fun=self.no_op)
        change = wallet.getnewaddress()

        plan = wallet.planconsolidation({"min_confirmations": 1, "max_inputs": 3, "target_utxo_count": 1})
        assert_equal(plan["input_count"], 3)
        named = outpoints(plan["inputs"])

        self.log.info("planconsolidation keeps the inputs it is given")
        for key in ("inputs", "selected_utxos"):
            replanned = wallet.planconsolidation({"min_confirmations": 1, key: plan[key]})
            assert_equal(outpoints(replanned["inputs"]), named)
        replanned = wallet.planconsolidation({"plan": plan})
        assert_equal(outpoints(replanned["inputs"]), named)

        self.log.info("A planned input that is locked now is refused, not spent outside the plan")
        locked = {"txid": plan["inputs"][0]["txid"], "vout": plan["inputs"][0]["vout"]}
        wallet.lockunspent(False, [locked])
        assert_raises_rpc_error(-8, "is not spendable here", wallet.createconsolidationtx,
                                {"plan": plan, "change_address": change})
        assert_raises_rpc_error(-8, "is not spendable here", wallet.planconsolidation, {"plan": plan})
        assert_raises_rpc_error(-8, "is not spendable here", wallet.estimateconsolidationfee,
                                {"plan": plan, "change_address": change})
        wallet.lockunspent(True, [locked])

        self.log.info("estimateconsolidationfee prices the plan's inputs")
        fee = wallet.estimateconsolidationfee({"plan": plan, "change_address": change})
        assert_equal(fee["input_count"], 3)
        assert fee["fee_atoms"] > 0, fee

        self.log.info("createconsolidationtx spends the plan's inputs")
        cons = wallet.createconsolidationtx({"plan": plan, "change_address": change})
        assert_equal(cons["fee_atoms"], fee["fee_atoms"])
        tx = node.decodepsbt(cons["psbt"])["tx"]
        assert_equal(sorted((i["txid"], i["vout"]) for i in tx["vin"]), named)


if __name__ == "__main__":
    WalletBcp1PlanInputsTest(__file__).main()
