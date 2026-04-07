#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal
import random

from test_framework.authproxy import JSONRPCException
from test_framework.shielded_utils import encrypt_and_unlock_wallet, ensure_ring_diversity, unlock_wallet
from test_framework.test_framework import BitcoinTestFramework


class WalletShieldedTopologySimTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--rounds", dest="rounds", type=int, default=12,
                            help="Number of simulation rounds (default: 12)")
        parser.add_argument("--sim-seed", dest="sim_seed", type=int, default=20260307,
                            help="Deterministic RNG seed (default: 20260307)")

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [[], [], []]
        self.rpc_timeout = 360

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _wallet(self, idx):
        return self.nodes[idx].get_wallet_rpc(f"w{idx}")

    def _mine_one(self, idx):
        miner_wallet = self._wallet(idx)
        self.generatetoaddress(self.nodes[idx], 1, miner_wallet.getnewaddress(), sync_fun=self.sync_all)

    def _ensure_full_mesh(self):
        for i in range(3):
            for j in range(i + 1, 3):
                try:
                    self.connect_nodes(i, j)
                except Exception:
                    pass
        self.wait_until(lambda: all(len(node.getpeerinfo()) >= 1 for node in self.nodes))
        self.sync_blocks(self.nodes)
        self.sync_mempools(self.nodes)

    def _partition_and_reorg(self, rnd):
        isolated = rnd.choice([1, 2])
        self.log.info(f"Partition node {isolated} and force competing tips")
        for peer in range(3):
            if peer == isolated:
                continue
            try:
                self.disconnect_nodes(isolated, peer)
            except Exception:
                pass

        # Majority side grows by 1 block.
        self.generatetoaddress(self.nodes[0], 1, self._wallet(0).getnewaddress(), sync_fun=self.no_op)
        # Isolated side grows by 2 blocks to force local preference.
        self.generatetoaddress(self.nodes[isolated], 2, self._wallet(isolated).getnewaddress(), sync_fun=self.no_op)

        for peer in range(3):
            if peer == isolated:
                continue
            self.connect_nodes(isolated, peer)
        self._ensure_full_mesh()

    def _restart_one(self, idx):
        self.log.info(f"Restart node {idx}")
        self.restart_node(idx)
        if f"w{idx}" not in self.nodes[idx].listwallets():
            self.nodes[idx].loadwallet(f"w{idx}")
        unlock_wallet(self.nodes[idx], f"w{idx}")
        self._ensure_full_mesh()

    def run_test(self):
        assert self.options.rounds > 0
        rnd = random.Random(self.options.sim_seed)

        for i in range(3):
            self.nodes[i].createwallet(wallet_name=f"w{i}", descriptors=True)
            encrypt_and_unlock_wallet(self.nodes[i], f"w{i}")
        self._ensure_full_mesh()

        self.log.info("Mine initial funds on node0 and fund peer wallets")
        mine0 = self._wallet(0).getnewaddress()
        self.generatetoaddress(self.nodes[0], 220, mine0, sync_fun=self.sync_all)

        for dst in [1, 2]:
            self._wallet(0).sendtoaddress(self._wallet(dst).getnewaddress(), Decimal("20.0"))
        self._mine_one(0)

        z_addrs = [self._wallet(i).z_getnewaddress() for i in range(3)]

        self.log.info("Create initial shielded balances and ring diversity")
        self._wallet(0).z_shieldfunds(Decimal("6.0"), z_addrs[0])
        self._wallet(1).z_shieldfunds(Decimal("4.0"), z_addrs[1])
        self._wallet(2).z_shieldfunds(Decimal("4.0"), z_addrs[2])
        self._mine_one(0)

        # Node 0 is the primary high-volume spender and must satisfy the
        # ring-size diversity target deterministically.
        ensure_ring_diversity(
            self,
            self.nodes[0],
            self._wallet(0),
            self._wallet(0).getnewaddress(),
            z_addrs[0],
            min_notes=12,
            topup_amount=Decimal("0.25"),
            sync_fun=self.sync_all,
        )

        # Peer wallets may start from a small transparent UTXO set. Try to seed
        # a smaller note floor, but continue if funding shape cannot satisfy it.
        for idx in [1, 2]:
            try:
                ensure_ring_diversity(
                    self,
                    self.nodes[idx],
                    self._wallet(idx),
                    self._wallet(idx).getnewaddress(),
                    z_addrs[idx],
                    min_notes=4,
                    topup_amount=Decimal("0.10"),
                    sync_fun=self.sync_all,
                )
            except AssertionError:
                self.log.info("Wallet w%d could not reach ring-diversity floor; continuing with best-effort state", idx)

        def zbal(idx):
            return Decimal(self._wallet(idx).z_getbalance()["balance"])

        self.log.info("Run deterministic topology simulation rounds")
        for i in range(self.options.rounds):
            op = rnd.choice(["z2z", "z2t", "shield", "restart", "partition_reorg"])

            if op == "restart":
                self._restart_one(rnd.randrange(3))
                continue

            if op == "partition_reorg":
                self._partition_and_reorg(rnd)
                continue

            src = rnd.randrange(3)
            dst = rnd.randrange(3)
            if dst == src:
                dst = (dst + 1) % 3

            try:
                if op == "z2z":
                    amount = Decimal(str(rnd.choice(["0.01", "0.02", "0.03"])))
                    if zbal(src) > amount + Decimal("0.03"):
                        self._wallet(src).z_sendmany([{"address": z_addrs[dst], "amount": amount}])
                elif op == "z2t":
                    amount = Decimal(str(rnd.choice(["0.01", "0.02"])))
                    if zbal(src) > amount + Decimal("0.03"):
                        self._wallet(src).z_sendmany(
                            [{"address": self._wallet(dst).getnewaddress(), "amount": amount}]
                        )
                else:
                    if self._wallet(src).getbalance() >= Decimal("0.20"):
                        self._wallet(src).z_shieldfunds(Decimal("0.20"), z_addrs[src])
            except JSONRPCException as e:
                if e.error.get("code") not in (-4, -6, -26):
                    raise

            self._mine_one(rnd.randrange(3))

            for idx in range(3):
                assert zbal(idx) >= Decimal("0")

        self.log.info("Finalize and assert convergence invariants")
        self.generatetoaddress(self.nodes[0], 2, self._wallet(0).getnewaddress(), sync_fun=self.sync_all)
        for _ in range(5):
            self.sync_mempools(self.nodes)
            if all(len(node.getrawmempool()) == 0 for node in self.nodes):
                break
            self._mine_one(0)
        self.sync_all()
        for idx in range(3):
            assert zbal(idx) >= Decimal("0")


if __name__ == "__main__":
    WalletShieldedTopologySimTest(__file__).main()
