#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""getblocktemplate filters over-cap shielded exits without dropping ordinary txs."""

from decimal import Decimal, ROUND_CEILING

from test_framework.blocktools import NORMAL_GBT_REQUEST_PARAMS
from test_framework.messages import COIN
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


C002_HEIGHT = 132
SUNSET_HEIGHT = 145
FEE_QUANTUM = Decimal("0.00001000")
EXACT_AMOUNT = Decimal("5.00000000")
RECOVERY_EXIT_FEE = Decimal("0.02000000")
SHIELD_FEE = Decimal("0.00010000")
SWEEP_NOTE_COUNT = 2


class MiningShieldedExitVelocityTemplateTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            f"-regtestshieldedmatrictdisableheight={C002_HEIGHT}",
            f"-regtestshieldedc002activationheight={C002_HEIGHT}",
            f"-regtestshieldedpoolcreditdisableheight={SUNSET_HEIGHT}",
            f"-regtestshieldedsunsetheight={SUNSET_HEIGHT}",
            f"-regtestshieldedrecoveryexitactivationheight={SUNSET_HEIGHT}",
            f"-regtestshieldedunshieldvelocityactivationheight={SUNSET_HEIGHT}",
        ]]
        self.rpc_timeout = 1800

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _mine_to_height(self, node, height, mine_addr):
        blocks = height - node.getblockcount()
        if blocks < 0:
            raise AssertionError(f"cannot mine backwards from {node.getblockcount()} to {height}")
        if blocks:
            self.generatetoaddress(node, blocks, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), height)

    def _canonical_fee(self, fee):
        return (fee / FEE_QUANTUM).to_integral_value(rounding=ROUND_CEILING) * FEE_QUANTUM

    def _amount_to_sat(self, amount):
        return int(Decimal(str(amount)) * COIN)

    def _seed_recovery_exit_wallet(self, node, funder, exit_wallet, mine_addr, exact_fee):
        shielded_addr = exit_wallet.z_getnewaddress()
        seed_total = EXACT_AMOUNT + exact_fee
        for _ in range(SWEEP_NOTE_COUNT):
            transparent_seed = seed_total + SHIELD_FEE
            fund_txid = funder.sendtoaddress(exit_wallet.getnewaddress(), transparent_seed)
            assert fund_txid in node.getrawmempool()
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
            shield = exit_wallet.z_shieldfunds(seed_total, shielded_addr, SHIELD_FEE)
            assert shield["txid"] in node.getrawmempool()
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        balance = exit_wallet.z_getbalance()
        assert_equal(Decimal(str(balance["balance"])), seed_total * SWEEP_NOTE_COUNT)
        assert_equal(balance["note_count"], SWEEP_NOTE_COUNT)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        node.createwallet(wallet_name="exit_recovery", descriptors=True)
        funder = encrypt_and_unlock_wallet(node, "funder")
        exit_recovery = encrypt_and_unlock_wallet(node, "exit_recovery")
        mine_addr = funder.getnewaddress()

        self.log.info("Fund a shielded source wallet before the C-002/sunset boundary")
        fund_trusted_transparent_balance(
            self,
            node,
            funder,
            mine_addr,
            Decimal("19.0"),
            maturity_blocks=C002_HEIGHT - 20,
            sync_fun=self.no_op,
        )
        assert_equal(node.getblockcount(), C002_HEIGHT - 19)

        exact_fee = self._canonical_fee(RECOVERY_EXIT_FEE)
        self.log.info("Seed a wallet for supported v2_recovery_exit transactions before C-002")
        self._seed_recovery_exit_wallet(node, funder, exit_recovery, mine_addr, exact_fee)

        z_source = funder.z_getnewaddress()
        shield = funder.z_shieldfunds(Decimal("3.0"), z_source)
        assert shield["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(
            self,
            node,
            funder,
            mine_addr,
            z_source,
            min_notes=16,
            topup_amount=Decimal("0.25"),
            sync_fun=self.no_op,
        )
        self._mine_to_height(node, C002_HEIGHT, mine_addr)

        self._mine_to_height(node, SUNSET_HEIGHT - 1, mine_addr)

        state = node.getshieldedstateinfo()
        assert_equal(state["velocity_cap_active"], True)
        assert_equal(state["velocity_min_cap_sat"], 0)
        assert_greater_than(state["remaining_window_capacity_sat"], 0)

        self.log.info("Leave one-note v2_recovery_exit sweep transactions pending over velocity capacity")
        sweep_dest = exit_recovery.getnewaddress()
        sweep = exit_recovery.z_sweeptotransparent(sweep_dest, SWEEP_NOTE_COUNT, exact_fee)
        assert sweep["complete"], sweep
        assert_equal(sweep["submitted_txs"], SWEEP_NOTE_COUNT)
        recovery_txids = {tx["txid"] for tx in sweep["transactions"]}
        for txid in recovery_txids:
            assert txid in node.getrawmempool()
            assert_equal(exit_recovery.z_viewtransaction(txid, True)["family"], "v2_recovery_exit")

        self.log.info("Add an ordinary transparent mempool transaction as a control")
        transparent_txid = funder.sendtoaddress(funder.getnewaddress(), Decimal("0.01000000"))
        assert transparent_txid in node.getrawmempool()

        shielded_exit_txids = recovery_txids
        pending_exit_value_balance = Decimal("0")
        for txid in recovery_txids:
            pending_exit_value_balance += Decimal(str(exit_recovery.z_viewtransaction(txid, True)["value_balance"]))
        assert_greater_than(
            self._amount_to_sat(pending_exit_value_balance),
            state["remaining_window_capacity_sat"],
        )

        self.log.info("getblocktemplate filters shielded exits but keeps the transparent transaction")
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        template_txids = {tx["txid"] for tx in template["transactions"]}
        assert_equal(template["mempool_validation_fallback"], False)
        assert transparent_txid in template_txids
        assert shielded_exit_txids.isdisjoint(template_txids)

        block_hash = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]
        block_txids = {tx["txid"] for tx in node.getblock(block_hash, 2)["tx"]}
        assert transparent_txid in block_txids
        assert shielded_exit_txids.isdisjoint(block_txids)

        mempool_after = set(node.getrawmempool())
        assert transparent_txid not in mempool_after
        assert shielded_exit_txids.issubset(mempool_after)


if __name__ == "__main__":
    MiningShieldedExitVelocityTemplateTest(__file__).main()
