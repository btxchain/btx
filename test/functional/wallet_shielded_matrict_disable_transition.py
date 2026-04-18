#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


DISABLE_HEIGHT = 132


class WalletShieldedMatRiCTDisableTransitionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            f"-regtestshieldedmatrictdisableheight={DISABLE_HEIGHT}",
        ]]
        self.rpc_timeout = 1200

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        node.createwallet(wallet_name="depositonly", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        deposit_wallet = encrypt_and_unlock_wallet(node, "depositonly")

        mine_addr = wallet.getnewaddress()
        self.log.info("Fund trusted transparent balance so the next shielded block lands exactly at the disable height")
        fund_trusted_transparent_balance(
            self,
            node,
            wallet,
            mine_addr,
            Decimal("8.0"),
            maturity_blocks=DISABLE_HEIGHT - 3,
            sync_fun=self.no_op,
        )
        assert_equal(node.getblockcount(), DISABLE_HEIGHT - 2)

        z_anchor = wallet.z_getnewaddress()
        self.log.info("Create a shielding transaction before activation, then cross the 132 disable boundary")
        shield_res = wallet.z_shieldfunds(Decimal("2.0"), z_anchor)
        assert shield_res["txid"] in node.getrawmempool()
        assert_equal(wallet.z_viewtransaction(shield_res["txid"])["family"], "v2_send")

        self.log.info("Populate the anonymity pool before the wallet switches to post-transition build rules")
        ensure_ring_diversity(
            self,
            node,
            wallet,
            mine_addr,
            z_anchor,
            min_notes=16,
            topup_amount=Decimal("0.25"),
        )
        assert_equal(node.getblockcount(), DISABLE_HEIGHT - 1)
        assert shield_res["txid"] not in node.getrawmempool()

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), DISABLE_HEIGHT)

        self.log.info("Verify shielded sends still succeed after the disable height has activated")
        post_transition_dest = wallet.z_getnewaddress()
        post_transition_send = wallet.z_sendmany([{"address": post_transition_dest, "amount": Decimal("0.50")}])
        assert post_transition_send["txid"] in node.getrawmempool()
        assert_equal(post_transition_send["family"], "shielded_v2")
        assert post_transition_send["family_redacted"]
        assert_equal(wallet.z_viewtransaction(post_transition_send["txid"])["family"], "shielded_v2")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert post_transition_send["txid"] not in node.getrawmempool()

        self.log.info("Verify post-transition coinbase shielding compatibility stays available for miners")
        coinbase_dest = wallet.z_getnewaddress()
        shield_coinbase = wallet.z_shieldcoinbase(coinbase_dest, None, 1, 6, "economical")
        assert shield_coinbase["txid"] in node.getrawmempool()
        assert_equal(shield_coinbase["shielding_inputs"], 1)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        compat_dest = wallet.z_getnewaddress()
        compat_plan = wallet.z_planshieldfunds(Decimal("0.50"), compat_dest)
        assert_equal(compat_plan["policy"]["selection_strategy"], "coinbase-largest-first")
        compat_shield = wallet.z_shieldfunds(Decimal("0.50"), compat_dest)
        assert compat_shield["txid"] in node.getrawmempool()
        assert compat_shield["transparent_inputs"] >= 1
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        compat_psbt = wallet.z_fundpsbt(Decimal("0.25"), wallet.z_getnewaddress())
        assert compat_psbt["psbt"]
        assert compat_psbt["transparent_inputs"] >= 1
        assert compat_psbt["shielded_outputs"] >= 1

        self.log.info("Verify post-transition non-coinbase transparent deposits still require bridge ingress")
        deposit_taddr = deposit_wallet.getnewaddress()
        wallet.sendtoaddress(deposit_taddr, Decimal("1.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        redesign_dest = deposit_wallet.z_getnewaddress()
        compatibility_error = (
            "post-fork direct transparent shielding is limited to mature coinbase outputs; "
            "use bridge ingress for general transparent deposits"
        )
        assert_raises_rpc_error(
            -4,
            compatibility_error,
            deposit_wallet.z_planshieldfunds,
            Decimal("0.50"),
            redesign_dest,
        )
        assert_raises_rpc_error(
            -4,
            compatibility_error,
            deposit_wallet.z_shieldfunds,
            Decimal("0.50"),
            redesign_dest,
        )
        assert_raises_rpc_error(
            -4,
            compatibility_error,
            deposit_wallet.z_fundpsbt,
            Decimal("0.50"),
            redesign_dest,
        )

        balance = wallet.z_getbalance()
        assert Decimal(balance["balance"]) > Decimal("0")
        assert int(balance["note_count"]) >= 1


if __name__ == "__main__":
    WalletShieldedMatRiCTDisableTransitionTest(__file__).main()
