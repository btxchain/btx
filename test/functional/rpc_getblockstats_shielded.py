#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""getblockstats on shielded blocks and empty-block-penalty blocks.

Fee statistics must count the shielded value balance the way consensus does
(CheckTxInputs), and `subsidy` must be the amount the block was allowed to
claim (GetBlockSubsidyForBlock), not the plain schedule. Both are checked
against the block itself: sum of coinbase outputs == subsidy + totalfee, and
totalfee == sum of the per-transaction fees `getblock <hash> 2` reports.
"""

from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
    unlock_wallet,
)
from test_framework.util import assert_equal, assert_greater_than

INITIAL_SUBSIDY = 20 * COIN
HALVING_INTERVAL = 150  # regtest


def sats(value):
    return int((Decimal(str(value)) * COIN).to_integral_value())


class GetBlockStatsShieldedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The statistics do not depend on MatMul. Under the default
        # -matmulvalidation=consensus a clean chain stops at height 99:
        # ConnectTip defers height 100 (see _initialize_chain in
        # test_framework.py). This test mines past 130, so move the MatMul
        # v4/RC heights out of reach.
        self.base_args = [
            "-autoshieldcoinbase=0",
            "-regtestshieldedmatrictdisableheight=500",
        ] + REGTEST_GENERIC_P2P_MATMUL_ARGS
        self.extra_args = [self.base_args]
        self.rpc_timeout = 1800

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def check_block(self, height):
        """Return getblockstats for `height` after checking it against the block."""
        node = self.nodes[0]
        blockhash = node.getblockhash(height)
        stats = node.getblockstats(blockhash)
        block = node.getblock(blockhash, 2)
        coinbase_value = sum(sats(out["value"]) for out in block["tx"][0]["vout"])
        fees = [sats(tx["fee"]) for tx in block["tx"][1:]]
        assert_equal(stats["totalfee"], sum(fees))
        if fees:
            assert_equal(stats["minfee"], min(fees))
            assert_equal(stats["maxfee"], max(fees))
        assert_equal(coinbase_value, stats["subsidy"] + stats["totalfee"])
        return stats, block

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        mine_addr = wallet.getnewaddress()

        self.log.info("Shield transparent funds into the pool")
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("10.0"), sync_fun=self.no_op
        )
        z_addr = wallet.z_getnewaddress()
        shield = wallet.z_shieldfunds(Decimal("2.0"), z_addr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        shield_height = node.getblockcount()
        stats, block = self.check_block(shield_height)
        assert shield["txid"] in [tx["txid"] for tx in block["tx"]]
        # The 2 BTX that went into the pool are not a fee.
        assert_greater_than(Decimal("0.01") * COIN, stats["totalfee"])

        ensure_ring_diversity(
            self, node, wallet, mine_addr, z_addr, min_notes=16, topup_amount=Decimal("0.25")
        )

        self.log.info("Unshield to a transparent address: no transparent inputs")
        t_dest = wallet.getnewaddress()
        unshield = wallet.z_sendmany([{"address": t_dest, "amount": Decimal("0.5")}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        unshield_height = node.getblockcount()
        stats, block = self.check_block(unshield_height)
        unshield_tx = next(tx for tx in block["tx"] if tx["txid"] == unshield["txid"])
        assert_equal(unshield_tx["vin"], [])
        assert_equal(sats(unshield_tx["fee"]), sats(unshield["fee"]))
        assert_greater_than(stats["totalfee"], 0)

        self.log.info("Fully shielded send: no transparent inputs or outputs")
        z_send = wallet.z_sendmany([{"address": wallet.z_getnewaddress(), "amount": Decimal("0.25")}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        stats, block = self.check_block(node.getblockcount())
        z_tx = next(tx for tx in block["tx"] if tx["txid"] == z_send["txid"])
        assert_equal(z_tx["vin"], [])
        assert_equal(z_tx["vout"], [])
        assert_greater_than(stats["totalfee"], 0)

        self.log.info("Blocks after the regtest empty-block penalty height")
        # Keep the blocks checked below inside one halving epoch.
        while (node.getblockcount() + 1) // HALVING_INTERVAL != (node.getblockcount() + 4) // HALVING_INTERVAL:
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        tip = node.getblockcount()
        penalty_height = tip + 1
        self.restart_node(0, extra_args=self.base_args + [
            f"-regtestemptyblocksubsidypenaltyheight={penalty_height}",
        ])
        node = self.nodes[0]
        node.loadwallet("shielded")
        wallet = unlock_wallet(node, "shielded")
        schedule = INITIAL_SUBSIDY >> (penalty_height // HALVING_INTERVAL)

        # A block with a transaction is not penalized.
        wallet.sendtoaddress(wallet.getnewaddress(), Decimal("1.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        stats, block = self.check_block(penalty_height)
        assert_equal(len(block["tx"]), 2)
        assert_equal(stats["subsidy"], schedule)

        # A coinbase-only block after a block with transactions claims half,
        # and a coinbase-only block after a coinbase-only block a quarter
        # (two halvings, the maximum).
        self.generatetoaddress(node, 3, mine_addr, sync_fun=self.no_op)
        for height, expected in ((penalty_height + 1, schedule // 2),
                                 (penalty_height + 2, schedule // 4),
                                 (penalty_height + 3, schedule // 4)):
            stats, block = self.check_block(height)
            assert_equal(len(block["tx"]), 1)
            assert_equal(stats["subsidy"], expected)


if __name__ == "__main__":
    GetBlockStatsShieldedTest(__file__).main()
