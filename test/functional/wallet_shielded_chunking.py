#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import encrypt_and_unlock_wallet, fund_trusted_transparent_balance
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than


class WalletShieldedChunkingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]
        self.rpc_timeout = 300

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funded", descriptors=True)
        node.createwallet(wallet_name="shielded", descriptors=True)
        funded_wallet = node.get_wallet_rpc("funded")
        wallet = encrypt_and_unlock_wallet(node, "shielded")

        mine_addr = funded_wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, funded_wallet, mine_addr, Decimal("15.00100000"), sync_fun=self.no_op
        )

        split_recipients = {}
        for _ in range(6):
            split_recipients[wallet.getnewaddress()] = Decimal("2.5")
        funded_wallet.sendmany("", split_recipients)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        z_dest = wallet.z_getnewaddress()
        options = {"max_inputs_per_chunk": 4}

        self.log.info("Plan a multi-chunk transparent-to-shielded sweep")
        plan = wallet.z_planshieldfunds(Decimal("10.0"), z_dest, Decimal("0.0001"), options)
        assert plan["estimated_chunk_count"] >= 2
        assert plan["policy"]["applied_max_inputs_per_chunk"] == 4
        assert plan["policy"]["selection_strategy"] == "largest-first"
        assert len(plan["chunks"]) == plan["estimated_chunk_count"]
        assert sum(chunk["transparent_inputs"] for chunk in plan["chunks"]) >= 5
        assert_greater_than(Decimal(plan["estimated_total_shielded"]), Decimal("9.9"))

        self.log.info("Execute the chunked sweep and verify all chunks hit the mempool")
        shield = wallet.z_shieldfunds(Decimal("10.0"), z_dest, Decimal("0.0001"), options)
        assert shield["chunk_count"] == plan["estimated_chunk_count"]
        assert len(shield["txids"]) == shield["chunk_count"]
        assert shield["policy"]["applied_max_inputs_per_chunk"] == 4
        assert shield["transparent_inputs"] == sum(chunk["transparent_inputs"] for chunk in shield["chunks"])
        assert_greater_than(Decimal(shield["amount"]), Decimal("9.9"))
        for txid in shield["txids"]:
            assert txid in node.getrawmempool()

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        balance = wallet.z_getbalance()
        assert_greater_than(Decimal(balance["balance"]), Decimal("9.9"))


if __name__ == "__main__":
    WalletShieldedChunkingTest(__file__).main()
