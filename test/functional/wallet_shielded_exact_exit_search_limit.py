#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Post-sunset exact transparent exits stop at a fixed search size.

After the shielded sunset, z_sendmany with only transparent recipients looks
for at most 8 notes of one shielded address whose values add up to the amount
plus the fee. The search keeps one table entry per reachable note count and
sum, so with many distinct note values it grows with C(values, 8), and it
holds cs_wallet and cs_shielded while it builds the table.

A wallet with 24 distinct note values at one address asks for more than it
holds. It must get a clear error once the table reaches its limit, instead of
building the whole table. A wallet with ten notes and a reachable amount still
exits as before.
"""

from decimal import Decimal
import random

from test_framework.shielded_utils import encrypt_and_unlock_wallet, fund_trusted_transparent_balance
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


C002_HEIGHT = 172
SUNSET_HEIGHT = 220
MANY_NOTES = 24
# Powers of two: every subset of these notes has its own sum.
FEW_NOTE_VALUES = [Decimal("0.01") * 2**i for i in range(10)]
EXIT_FEE = Decimal("0.00500000")
LIMIT_ERROR = "exact shielded exit search exceeded its limit; use z_sweeptotransparent or send a smaller amount"


class WalletShieldedExactExitSearchLimitTest(BitcoinTestFramework):
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
            f"-regtestshieldedv2sendzerooutputexitactivationheight={SUNSET_HEIGHT + 1}",
        ]]
        self.rpc_timeout = 1800

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def shield_notes(self, node, funder, zaddr, values, mine_addr):
        for i, value in enumerate(values):
            funder.z_shieldfunds(value, zaddr)
            if i % 4 == 3:
                self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

    def run_test(self):
        node = self.nodes[0]
        for name in ("funder", "many", "few"):
            node.createwallet(wallet_name=name, descriptors=True)
        funder = encrypt_and_unlock_wallet(node, "funder")
        many = encrypt_and_unlock_wallet(node, "many")
        few = encrypt_and_unlock_wallet(node, "few")
        mine_addr = funder.getnewaddress()
        fund_trusted_transparent_balance(self, node, funder, mine_addr, Decimal("1.0"),
                                         maturity_blocks=C002_HEIGHT - 4, sync_fun=self.no_op)
        self.generatetoaddress(node, C002_HEIGHT + 1 - node.getblockcount(), mine_addr, sync_fun=self.no_op)

        self.log.info(f"Before the sunset, give one address of wallet many {MANY_NOTES} notes with distinct values")
        rng = random.Random(304)
        many_values = set()
        while len(many_values) < MANY_NOTES:
            many_values.add(Decimal(rng.randint(1_000_000, 12_000_000)) / Decimal(100_000_000))
        self.shield_notes(node, funder, many.z_getnewaddress(), sorted(many_values), mine_addr)
        self.log.info("and one address of wallet few ten notes")
        self.shield_notes(node, funder, few.z_getnewaddress(), FEW_NOTE_VALUES, mine_addr)
        assert_equal(many.z_getbalance()["note_count"], MANY_NOTES)
        assert_equal(few.z_getbalance()["note_count"], len(FEW_NOTE_VALUES))
        assert node.getblockcount() < SUNSET_HEIGHT
        self.generatetoaddress(node, SUNSET_HEIGHT + 1 - node.getblockcount(), mine_addr, sync_fun=self.no_op)

        self.log.info("An exact exit that needs the whole table stops at the limit")
        balance = Decimal(str(many.z_getbalance()["balance"]))
        assert_raises_rpc_error(-4, LIMIT_ERROR, many.z_sendmany,
                                [{"address": many.getnewaddress(), "amount": balance + 1}], EXIT_FEE)
        assert_equal(many.z_getbalance()["note_count"], MANY_NOTES)

        self.log.info("A wallet with a few notes and a reachable amount exits as before")
        chosen = [FEW_NOTE_VALUES[0], FEW_NOTE_VALUES[2], FEW_NOTE_VALUES[5]]
        amount = sum(chosen) - EXIT_FEE
        dest = few.getnewaddress()
        tx = few.z_sendmany([{"address": dest, "amount": amount}], EXIT_FEE)
        assert tx["txid"] in node.getrawmempool()
        assert_equal(len(few.z_viewtransaction(tx["txid"], True)["spends"]), len(chosen))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(few.getreceivedbyaddress(dest), amount)


if __name__ == "__main__":
    WalletShieldedExactExitSearchLimitTest(__file__).main()
