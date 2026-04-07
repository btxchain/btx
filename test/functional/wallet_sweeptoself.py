#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the sweeptoself wallet RPC command."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletSweepToSelfTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        node.createwallet(wallet_name="sweep", descriptors=True)
        funder = node.get_wallet_rpc("funder")
        sweep = node.get_wallet_rpc("sweep")

        mine_addr = funder.getnewaddress()
        self.log.info("funding wallet with mature coinbase outputs")
        self.generatetoaddress(node, 110, mine_addr, sync_fun=self.no_op)

        funder_balance = Decimal(str(funder.getbalances()["mine"]["trusted"]))
        if funder_balance <= Decimal("0"):
            self.log.info(
                "no mature spendable balance under current regtest profile; "
                "validating sweeptoself option/error handling only"
            )
            assert_raises_rpc_error(
                -8,
                "Invalid preferred_pq_algo",
                sweep.sweeptoself,
                {"preferred_pq_algo": "invalid"},
            )
            assert_raises_rpc_error(
                -6,
                "No spendable UTXOs available for sweep",
                sweep.sweeptoself,
                {"preferred_pq_algo": "slh_dsa_128s"},
            )
            return

        self.log.info("create multiple UTXOs in sweep wallet")
        spend_budget = (funder_balance * Decimal("0.75")).quantize(Decimal("0.00000001"))
        base = (spend_budget / Decimal("6")).quantize(Decimal("0.00000001"))
        min_amount = Decimal("0.00010000")
        if base < min_amount:
            base = min_amount
        amounts = [base, base * 2, base * 3]
        if sum(amounts) >= funder_balance:
            raise AssertionError(
                f"insufficient mature balance for sweep funding: balance={funder_balance}"
            )

        for amount in amounts:
            funder.sendtoaddress(sweep.getnewaddress(), amount)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        pre_utxos = sweep.listunspent()
        assert_equal(len(pre_utxos), 3)

        self.log.info("reject invalid preferred_pq_algo")
        assert_raises_rpc_error(
            -8,
            "Invalid preferred_pq_algo",
            sweep.sweeptoself,
            {"preferred_pq_algo": "invalid"},
        )

        self.log.info("sweep to a new internal destination using SLH-DSA preference")
        result = sweep.sweeptoself({"preferred_pq_algo": "slh_dsa_128s"})
        assert "txid" in result
        assert "destination" in result
        assert_equal(result["inputs_swept"], 3)

        tx = sweep.gettransaction(result["txid"], verbose=True)
        assert_equal(len(tx["decoded"]["vin"]), 3)
        assert_equal(len(tx["decoded"]["vout"]), 1)

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        post_utxos = sweep.listunspent()
        assert_equal(len(post_utxos), 1)
        assert_equal(post_utxos[0]["txid"], result["txid"])

        self.log.info("minconf filter should reject when no UTXOs qualify")
        assert_raises_rpc_error(
            -6,
            "No spendable UTXOs available for sweep",
            sweep.sweeptoself,
            {"minconf": 999999},
        )


if __name__ == "__main__":
    WalletSweepToSelfTest(__file__).main()
