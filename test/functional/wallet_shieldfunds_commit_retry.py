#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""z_shieldfunds retries a refused chunk with fewer inputs and reports it.

The transparent inputs come from one unconfirmed parent. The ancestor size
limit refuses a chunk with eight of them and accepts one with four, so the
first commit fails and the retry with a halved chunk is accepted.
"""

from decimal import Decimal

from test_framework.shielded_utils import encrypt_and_unlock_wallet, fund_trusted_transparent_balance
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class WalletShieldFundsCommitRetryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Legacy transparent-input shielding, as in wallet_shielded_chunking.py.
        # The parent is about 4.2 kvB, a four-input chunk about 30 kvB and an
        # eight-input chunk about 45 kvB.
        self.extra_args = [["-regtestshieldedmatrictdisableheight=500", "-limitancestorsize=40"]]
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
        funded_wallet.sendtoaddress(wallet.getnewaddress(), Decimal("15.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Split into eight outputs of one unconfirmed parent")
        parent = wallet.sendmany("", {wallet.getnewaddress(): Decimal("1.8") for _ in range(8)})
        assert parent in node.getrawmempool()

        z_dest = wallet.z_getnewaddress()
        options = {"max_inputs_per_chunk": 8}
        plan = wallet.z_planshieldfunds(Decimal("14.0"), z_dest, None, options)
        assert_equal([chunk["transparent_inputs"] for chunk in plan["chunks"]], [8])

        self.log.info("The eight-input chunk is refused; the four-input retry must be reported as sent")
        shield = wallet.z_shieldfunds(Decimal("14.0"), z_dest, None, options)
        assert_equal(shield["complete"], True)
        assert_equal(shield["policy"]["applied_max_inputs_per_chunk"], 4)
        assert_equal([chunk["transparent_inputs"] for chunk in shield["chunks"]], [4, 4])
        mempool = node.getrawmempool()
        for txid in shield["txids"]:
            assert txid in mempool
        assert_equal(len(mempool), 1 + len(shield["txids"]))

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_greater_than(Decimal(wallet.z_getbalance()["balance"]), Decimal("13.9"))


if __name__ == "__main__":
    WalletShieldFundsCommitRetryTest(__file__).main()
