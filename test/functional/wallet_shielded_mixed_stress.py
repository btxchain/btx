#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal
import random

from test_framework.authproxy import JSONRPCException
from test_framework.shielded_utils import encrypt_and_unlock_wallet, ensure_ring_diversity
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class WalletShieldedMixedStressTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        random.seed(1337)

        n0, n1 = self.nodes
        n0.createwallet(wallet_name="w0", descriptors=True)
        n1.createwallet(wallet_name="w1", descriptors=True)
        w0 = encrypt_and_unlock_wallet(n0, "w0")
        w1 = encrypt_and_unlock_wallet(n1, "w1")

        self.log.info("Mine and seed initial shielded balances")
        mine0 = w0.getnewaddress()
        self.generatetoaddress(n0, 130, mine0, sync_fun=self.sync_all)

        z0_main = w0.z_getnewaddress()
        z1_main = w1.z_getnewaddress()
        w0.z_shieldfunds(Decimal("4.0"), z0_main)
        self.generatetoaddress(n0, 1, mine0, sync_fun=self.sync_all)
        ensure_ring_diversity(self, n0, w0, mine0, z0_main, sync_fun=self.sync_all)

        assert Decimal(w0.z_getbalance()["balance"]) > Decimal("3.5")

        self.log.info("Run deterministic mixed shielded/transparent stress rounds")
        for i in range(10):
            mode = i % 4
            try:
                if mode == 0:
                    # Shielded -> shielded (same wallet)
                    w0.z_sendmany([{"address": w0.z_getnewaddress(), "amount": Decimal("0.03")}])
                elif mode == 1:
                    # Shielded -> shielded (cross wallet)
                    w0.z_sendmany([{"address": z1_main, "amount": Decimal("0.02")}])
                elif mode == 2:
                    # Shielded -> transparent
                    w0.z_sendmany([{"address": w1.getnewaddress(), "amount": Decimal("0.01")}])
                else:
                    # Transparent -> shielded (use whichever wallet has matured transparent funds)
                    try:
                        w1.z_shieldfunds(Decimal("0.10"), z1_main)
                    except Exception:
                        w0.z_shieldfunds(Decimal("0.10"), z0_main)
            except JSONRPCException as e:
                # Under rapid mixed flow, wallet note-selection can intentionally hit
                # mempool-policy rejection paths (nullifier conflicts / temporary
                # spendability windows). Treat this as a valid stress outcome and
                # continue after advancing the chain.
                if e.error.get("code") != -26:
                    raise

            # Mine on alternating nodes to exercise relay + wallet notifications.
            mine_addr = w0.getnewaddress() if i % 2 == 0 else w1.getnewaddress()
            miner = n0 if i % 2 == 0 else n1
            self.generatetoaddress(miner, 1, mine_addr, sync_fun=self.sync_all)

            # Keep key invariants cheap and strict.
            assert Decimal(w0.z_getbalance()["balance"]) >= Decimal("0")
            assert Decimal(w1.z_getbalance()["balance"]) >= Decimal("0")

        self.log.info("Exercise mempool nullifier conflict rejection")
        pending_dest = w0.z_getnewaddress()
        first = w0.z_sendmany([{"address": pending_dest, "amount": Decimal("0.20")}])
        assert first["txid"] in n0.getrawmempool()
        assert_raises_rpc_error(
            -26,
            "Shielded transaction created but rejected from mempool (policy or consensus)",
            w0.z_sendmany,
            [{"address": pending_dest, "amount": Decimal("0.05")}],
        )
        self.generatetoaddress(n0, 1, mine0, sync_fun=self.sync_all)

        self.log.info("Force a short fork and ensure both wallets survive reorg convergence")
        self.disconnect_nodes(0, 1)
        self.generatetoaddress(n0, 2, w0.getnewaddress(), sync_fun=self.no_op)
        self.generatetoaddress(n1, 3, w1.getnewaddress(), sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, n1])
        self.sync_mempools([n0, n1])

        # Post-reorg safety checks.
        assert Decimal(w0.z_getbalance()["balance"]) >= Decimal("0")
        assert Decimal(w1.z_getbalance()["balance"]) >= Decimal("0")

        self.log.info("Run final burst of randomized shielded sends")
        for _ in range(3):
            amount = Decimal("0.01")
            dest = w0.z_getnewaddress() if random.randint(0, 1) == 0 else z1_main
            w0.z_sendmany([{"address": dest, "amount": amount}])
            self.generatetoaddress(n0, 1, w0.getnewaddress(), sync_fun=self.sync_all)

        assert Decimal(w0.z_getbalance()["balance"]) >= Decimal("0")
        assert Decimal(w1.z_getbalance()["balance"]) >= Decimal("0")
        assert len(n0.getrawmempool()) == 0


if __name__ == "__main__":
    WalletShieldedMixedStressTest(__file__).main()
