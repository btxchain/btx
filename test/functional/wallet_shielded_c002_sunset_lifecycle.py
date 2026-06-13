#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Compressed C-002/sunset shielded lifecycle simulation.

Regtest lowers the C-002 and sunset gates to prove that shielded notes created
before C-002 remain spendable through the C-002 proof transition, and that the
v0.32.2 sunset blocks new shielded credits while exact transparent exits remain
available at and beyond the sunset boundary.
"""

from decimal import Decimal, ROUND_CEILING

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


C002_HEIGHT = 132
SUNSET_HEIGHT = 145
EXACT_AMOUNT = Decimal("0.50000001")
FEE_QUANTUM = Decimal("0.00001000")


class WalletShieldedC002SunsetLifecycleTest(BitcoinTestFramework):
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

    def _seed_exact_exit_wallet(self, node, funder, exit_wallet, exit_addr, mine_addr, exact_fee):
        seed_total = EXACT_AMOUNT + exact_fee
        second = funder.z_sendmany([{"address": exit_addr, "amount": seed_total}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert second["txid"] not in node.getrawmempool()
        assert_equal(Decimal(str(exit_wallet.z_getbalance()["balance"])), seed_total)

    def _exact_exit(self, node, wallet, mine_addr, exact_fee):
        balance = wallet.z_getbalance()
        assert_equal(Decimal(str(balance["balance"])), EXACT_AMOUNT + exact_fee)
        assert_equal(balance["note_count"], 1)
        t_dest = wallet.getnewaddress()
        tx = wallet.z_sendmany(
            [{"address": t_dest, "amount": EXACT_AMOUNT}],
            exact_fee,
        )
        assert tx["txid"] in node.getrawmempool()
        assert tx["spends"] >= 1
        assert_equal(Decimal(str(tx["fee"])), exact_fee)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(wallet.getreceivedbyaddress(t_dest), EXACT_AMOUNT)
        return tx["txid"]

    def _assert_sunset_ingress_guards(self, wallet, zaddr, height):
        assert_raises_rpc_error(
            -4,
            f"z_shieldfunds is disabled at height {height}",
            wallet.z_shieldfunds,
            Decimal("0.1"),
            zaddr,
        )
        assert_raises_rpc_error(
            -4,
            f"z_sendmany with shielded recipients is disabled at height {height}",
            wallet.z_sendmany,
            [{"address": zaddr, "amount": Decimal("0.1")}],
        )

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        node.createwallet(wallet_name="exit_boundary", descriptors=True)
        node.createwallet(wallet_name="exit_post", descriptors=True)
        node.createwallet(wallet_name="exit_replace", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        exit_boundary = encrypt_and_unlock_wallet(node, "exit_boundary")
        exit_post = encrypt_and_unlock_wallet(node, "exit_post")
        exit_replace = encrypt_and_unlock_wallet(node, "exit_replace")

        mine_addr = wallet.getnewaddress()
        self.log.info("Create pre-C-002 shielded notes and ring diversity")
        fund_trusted_transparent_balance(
            self,
            node,
            wallet,
            mine_addr,
            Decimal("10.0"),
            maturity_blocks=C002_HEIGHT - 4,
            sync_fun=self.no_op,
        )
        assert_equal(node.getblockcount(), C002_HEIGHT - 3)

        z_source = wallet.z_getnewaddress()
        shield = wallet.z_shieldfunds(Decimal("3.0"), z_source)
        assert shield["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(
            self,
            node,
            wallet,
            mine_addr,
            z_source,
            min_notes=16,
            topup_amount=Decimal("0.25"),
            sync_fun=self.no_op,
        )
        assert_equal(node.getblockcount(), C002_HEIGHT - 1)
        assert Decimal(str(wallet.z_getbalance()["balance"])) > Decimal("0")

        self.log.info("Spend pre-C-002 notes into the exact C-002 block")
        c002_dest = wallet.z_getnewaddress()
        c002_send = wallet.z_sendmany([{"address": c002_dest, "amount": Decimal("0.20")}])
        assert c002_send["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), C002_HEIGHT)

        self.log.info("Verify ordinary transparent unshield still works before sunset")
        transparent_dest = wallet.getnewaddress()
        pre_sunset_unshield = wallet.z_sendmany([{"address": transparent_dest, "amount": Decimal("0.10")}])
        assert pre_sunset_unshield["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(wallet.getreceivedbyaddress(transparent_dest), Decimal("0.10"))
        exact_fee = self._canonical_fee(max(Decimal(str(pre_sunset_unshield["fee"])), Decimal("0.00012")))

        self.log.info("Seed exact-exit wallets before the sunset")
        boundary_zaddr = exit_boundary.z_getnewaddress()
        post_zaddr = exit_post.z_getnewaddress()
        replace_zaddr = exit_replace.z_getnewaddress()
        self._seed_exact_exit_wallet(node, wallet, exit_boundary, boundary_zaddr, mine_addr, exact_fee)
        self._seed_exact_exit_wallet(node, wallet, exit_post, post_zaddr, mine_addr, exact_fee)
        self._seed_exact_exit_wallet(node, wallet, exit_replace, replace_zaddr, mine_addr, exact_fee)
        assert node.getblockcount() < SUNSET_HEIGHT - 1

        self.log.info("At next-block sunset, new shielded credits are blocked but exact transparent exit is accepted")
        self._mine_to_height(node, SUNSET_HEIGHT - 1, mine_addr)
        guard_zaddr = wallet.z_getnewaddress()
        self._assert_sunset_ingress_guards(wallet, guard_zaddr, SUNSET_HEIGHT)
        boundary_exit_txid = self._exact_exit(node, exit_boundary, mine_addr, exact_fee)
        assert_equal(node.getblockcount(), SUNSET_HEIGHT)
        assert_equal(exit_boundary.gettransaction(boundary_exit_txid)["confirmations"], 1)

        self.log.info("Beyond sunset, ingress remains blocked and exact transparent exits remain spendable")
        self._assert_sunset_ingress_guards(wallet, guard_zaddr, SUNSET_HEIGHT + 1)
        post_exit_txid = self._exact_exit(node, exit_post, mine_addr, exact_fee)
        assert_equal(node.getblockcount(), SUNSET_HEIGHT + 1)
        assert_equal(exit_post.gettransaction(post_exit_txid)["confirmations"], 1)

        self.log.info("Replace a stuck recovery-exit with the same note and a higher fee")
        low_fee = exact_fee
        high_fee = exact_fee + FEE_QUANTUM
        original_dest = exit_replace.getnewaddress()
        replacement_dest = exit_replace.getnewaddress()
        original_exit = exit_replace.z_sendmany(
            [{"address": original_dest, "amount": EXACT_AMOUNT}],
            low_fee,
        )
        assert original_exit["txid"] in node.getrawmempool()
        assert_equal(exit_replace.z_viewtransaction(original_exit["txid"], True)["family"], "v2_recovery_exit")
        replacement_amount = EXACT_AMOUNT - FEE_QUANTUM
        replacement_exit = exit_replace.z_sendmany(
            [{"address": replacement_dest, "amount": replacement_amount}],
            high_fee,
            [],
            None,
            None,
            original_exit["txid"],
        )
        assert replacement_exit["txid"] in node.getrawmempool()
        assert original_exit["txid"] not in node.getrawmempool()
        assert_equal(exit_replace.z_viewtransaction(replacement_exit["txid"], True)["family"], "v2_recovery_exit")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(exit_replace.getreceivedbyaddress(replacement_dest), replacement_amount)

        self.log.info("Non-exact post-sunset transparent exits fail before the ordinary V2_SEND fallback")
        assert_raises_rpc_error(
            -4,
            "after the shielded sunset",
            wallet.z_sendmany,
            [{"address": wallet.getnewaddress(), "amount": Decimal("0.12345678")}],
            exact_fee,
        )

        final_balance = wallet.z_getbalance()
        assert Decimal(str(final_balance["balance"])) >= Decimal("0")
        assert int(final_balance["note_count"]) >= 0


if __name__ == "__main__":
    WalletShieldedC002SunsetLifecycleTest(__file__).main()
