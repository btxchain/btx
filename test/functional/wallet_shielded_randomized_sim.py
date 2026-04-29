#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal
import random

from test_framework.shielded_utils import encrypt_and_unlock_wallet, ensure_ring_diversity, unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletShieldedRandomizedSimTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--rounds", dest="rounds", type=int, default=16,
                            help="Number of randomized operation rounds to execute (default: 16)")
        parser.add_argument("--sim-seed", dest="sim_seed", type=int, default=20260306,
                            help="Deterministic RNG seed for randomized operations (default: 20260306)")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-regtestshieldedmatrictdisableheight=500"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        assert self.options.rounds > 0
        rnd = random.Random(self.options.sim_seed)
        n0 = self.nodes[0]
        n0.createwallet(wallet_name="sim0", descriptors=True)
        w0 = encrypt_and_unlock_wallet(n0, "sim0")

        self.log.info("Mine transparent funds and create initial shielded liquidity")
        mine0 = w0.getnewaddress()
        self.generatetoaddress(n0, 170, mine0, sync_fun=self.no_op)

        z0 = w0.z_getnewaddress()
        w0.z_shieldfunds(Decimal("8.0"), z0)
        self.generatetoaddress(n0, 1, mine0, sync_fun=self.no_op)
        ensure_ring_diversity(self, n0, w0, mine0, z0)

        expected_received = {}

        def ensure_shielded_balance(min_required: Decimal) -> None:
            balance = Decimal(w0.z_getbalance()["balance"])
            if balance >= min_required:
                return
            refill = min_required + Decimal("0.8")
            self.log.info(f"Refilling shielded pool balance by {refill}")
            w0.z_shieldfunds(refill, z0)
            self.generatetoaddress(n0, 1, mine0, sync_fun=self.no_op)

        self.log.info("Run deterministic randomized mixed shielded workload")
        rounds = self.options.rounds
        for i in range(rounds):
            operation = rnd.choice(["shield_self", "unshield", "topup"]) if i % 5 else "restart"

            if operation == "restart":
                self.restart_node(0)
                n0 = self.nodes[0]
                if "sim0" not in n0.listwallets():
                    n0.loadwallet("sim0")
                w0 = unlock_wallet(n0, "sim0")
                continue

            if operation == "topup":
                topup_amount = Decimal(str(rnd.choice(["0.2", "0.25", "0.3"])))
                w0.z_shieldfunds(topup_amount, z0)
                self.generatetoaddress(n0, 1, mine0, sync_fun=self.no_op)
                continue

            amount = Decimal(str(rnd.choice(["0.02", "0.03", "0.04", "0.05"])))
            ensure_shielded_balance(amount + Decimal("0.03"))
            ensure_ring_diversity(self, n0, w0, mine0, z0)

            if operation == "shield_self":
                dest = w0.z_getnewaddress()
                txid = w0.z_sendmany([{"address": dest, "amount": amount}])["txid"]
            else:
                dest = w0.getnewaddress()
                txid = w0.z_sendmany([{"address": dest, "amount": amount}])["txid"]
                expected_received[dest] = expected_received.get(dest, Decimal("0")) + amount

            assert txid in n0.getrawmempool()
            self.generatetoaddress(n0, 1, mine0, sync_fun=self.no_op)

        self.log.info("Validate deterministic transparent receipts and final shielded usability")
        observed_total = Decimal("0")
        expected_total = Decimal("0")
        for addr, expected in expected_received.items():
            observed_total += w0.getreceivedbyaddress(addr)
            expected_total += expected
        assert_equal(observed_total, expected_total)

        assert Decimal(w0.z_getbalance()["balance"]) >= Decimal("0")
        assert len(w0.z_listunspent(0, 9999999, True)) > 0


if __name__ == "__main__":
    WalletShieldedRandomizedSimTest(__file__).main()
