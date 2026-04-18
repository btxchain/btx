#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal
import random

from test_framework.authproxy import JSONRPCException
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework


class WalletShieldedLonghaulSimTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--rounds", dest="rounds", type=int, default=8,
                            help="Number of randomized workload rounds (default: 8)")
        parser.add_argument("--sim-seed", dest="sim_seed", type=int, default=20260307,
                            help="Deterministic RNG seed (default: 20260307)")

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        assert self.options.rounds > 0
        rnd = random.Random(self.options.sim_seed)

        n0, n1 = self.nodes
        n0.createwallet(wallet_name="w0", descriptors=True)
        n1.createwallet(wallet_name="w1", descriptors=True)
        w0 = encrypt_and_unlock_wallet(n0, "w0")
        w1 = encrypt_and_unlock_wallet(n1, "w1")

        self.log.info("Seed transparent funds and initial shielded liquidity")
        mine0 = w0.getnewaddress()
        mine1 = w1.getnewaddress()
        self.generatetoaddress(n0, 130, mine0, sync_fun=self.sync_all)

        z0_main = w0.z_getnewaddress()
        z1_main = w1.z_getnewaddress()
        self.log.info("Pre-seed shielded commitments so ring-16 spends have enough decoy diversity")
        for _ in range(16):
            w0.z_shieldfunds(Decimal("1.0"), z0_main)
        self.generatetoaddress(n0, 1, mine0, sync_fun=self.sync_all)

        bootstrap_complete = False
        for attempt in range(6):
            if attempt > 0:
                for _ in range(4):
                    w0.z_shieldfunds(Decimal("1.0"), z0_main)
                self.generatetoaddress(n0, 1, mine0, sync_fun=self.sync_all)
            try:
                w0.z_sendmany([{"address": z1_main, "amount": Decimal("0.50")}])
                self.generatetoaddress(n0, 1, mine0, sync_fun=self.sync_all)
                bootstrap_complete = True
                break
            except JSONRPCException as e:
                if e.error.get("code") not in (-4, -6, -26):
                    raise
                self.log.info("Bootstrap shielded transfer attempt %d failed with %s; retrying",
                              attempt + 1, e.error.get("code"))
                self.generatetoaddress(n0, 2, mine0, sync_fun=self.sync_all)
        assert bootstrap_complete

        def zbal(wallet):
            return Decimal(wallet.z_getbalance()["balance"])

        def mine_one(height_index):
            if height_index % 2 == 0:
                self.generatetoaddress(n0, 1, w0.getnewaddress(), sync_fun=self.sync_all)
            else:
                self.generatetoaddress(n1, 1, w1.getnewaddress(), sync_fun=self.sync_all)

        self.log.info("Run deterministic randomized longhaul mixed workload")
        for i in range(self.options.rounds):
            op = rnd.choice(["z2z_0to1", "z2z_1to0", "z2t_0to1", "shield_1"])

            try:
                if op == "z2z_0to1":
                    amt = Decimal(str(rnd.choice(["0.02", "0.03", "0.04", "0.05"])))
                    if zbal(w0) > amt + Decimal("0.03"):
                        w0.z_sendmany([{"address": z1_main, "amount": amt}])
                elif op == "z2z_1to0":
                    amt = Decimal(str(rnd.choice(["0.01", "0.02", "0.03"])))
                    if zbal(w1) > amt + Decimal("0.03"):
                        w1.z_sendmany([{"address": z0_main, "amount": amt}])
                elif op == "z2t_0to1":
                    amt = Decimal(str(rnd.choice(["0.01", "0.02", "0.03"])))
                    if zbal(w0) > amt + Decimal("0.03"):
                        w0.z_sendmany([{"address": w1.getnewaddress(), "amount": amt}])
                elif op == "shield_1":
                    # Re-shield transparent receipts on wallet 1 as they accumulate.
                    if w1.getbalance() >= Decimal("0.20"):
                        w1.z_shieldfunds(Decimal("0.20"), z1_main)
            except JSONRPCException as e:
                # Expected stress outcomes: temporary insufficient funds windows,
                # mempool-policy rejections, or immature-coinbase shielding attempts.
                if e.error.get("code") not in (-4, -6, -26):
                    raise

            mine_one(i)

            assert zbal(w0) >= Decimal("0")
            assert zbal(w1) >= Decimal("0")

        self.log.info("Finalize chain and verify convergence invariants")
        self.generatetoaddress(n0, 2, w0.getnewaddress(), sync_fun=self.sync_all)
        assert len(n0.getrawmempool()) == 0
        assert len(n1.getrawmempool()) == 0
        assert zbal(w0) >= Decimal("0")
        assert zbal(w1) >= Decimal("0")


if __name__ == "__main__":
    WalletShieldedLonghaulSimTest(__file__).main()
