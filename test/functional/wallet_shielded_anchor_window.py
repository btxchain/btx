#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import encrypt_and_unlock_wallet, ensure_ring_diversity
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletShieldedAnchorWindowTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-walletbroadcast=0", "-regtestshieldedmatrictdisableheight=500"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _broadcast_wallet_tx(self, wallet, node, txid):
        tx_hex = wallet.gettransaction(txid)["hex"]
        assert tx_hex
        broadcasted = node.sendrawtransaction(tx_hex)
        assert_equal(broadcasted, txid)
        return broadcasted

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        node.createwallet(wallet_name="churn", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        churn_wallet = encrypt_and_unlock_wallet(node, "churn")

        mine_addr = wallet.getnewaddress()
        self.generatetoaddress(node, 130, mine_addr, sync_fun=self.no_op)

        self.log.info("Fund transparent balance for churn wallet")
        churn_taddr = churn_wallet.getnewaddress()
        churn_fund_txid = wallet.sendtoaddress(churn_taddr, Decimal("2.0"))
        self._broadcast_wallet_tx(wallet, node, churn_fund_txid)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Fund shielded pool using local-only wallet tx + explicit broadcast")
        z_from = wallet.z_getnewaddress()
        z_to = wallet.z_getnewaddress()
        shield = wallet.z_shieldfunds(Decimal("2.0"), z_from)
        shield_txid = shield["txid"]
        assert shield_txid not in node.getrawmempool()
        self._broadcast_wallet_tx(wallet, node, shield_txid)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, wallet, mine_addr, z_from)

        self.log.info("Anchor inside window remains valid")
        recent_send = wallet.z_sendmany([{"address": z_to, "amount": Decimal("1.0")}])
        recent_txid = recent_send["txid"]
        assert recent_txid not in node.getrawmempool()
        self.generatetoaddress(node, 5, mine_addr, sync_fun=self.no_op)
        self._broadcast_wallet_tx(wallet, node, recent_txid)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Transparent-only blocks do not invalidate an unchanged anchor root")
        z_late = wallet.z_getnewaddress()
        stale_send = wallet.z_sendmany([{"address": z_late, "amount": Decimal("0.1")}])
        stale_txid = stale_send["txid"]
        assert stale_txid not in node.getrawmempool()

        self.generatetoaddress(node, 101, mine_addr, sync_fun=self.no_op)
        stale_hex = wallet.gettransaction(stale_txid)["hex"]
        assert_equal(node.sendrawtransaction(stale_hex), stale_txid)

        self.log.info("Anchor older than SHIELDED_ANCHOR_DEPTH is rejected once roots advance")
        z_stale_source = wallet.z_getnewaddress()
        shield_stale = wallet.z_shieldfunds(Decimal("0.3"), z_stale_source)
        shield_stale_txid = shield_stale["txid"]
        assert shield_stale_txid not in node.getrawmempool()
        self._broadcast_wallet_tx(wallet, node, shield_stale_txid)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        z_stale_dest = wallet.z_getnewaddress()
        stale_anchor_send = wallet.z_sendmany([{"address": z_stale_dest, "amount": Decimal("0.1")}])
        stale_anchor_txid = stale_anchor_send["txid"]
        assert stale_anchor_txid not in node.getrawmempool()

        z_churn_source = churn_wallet.z_getnewaddress()
        churn_shield = churn_wallet.z_shieldfunds(Decimal("1.0"), z_churn_source)
        churn_shield_txid = churn_shield["txid"]
        assert churn_shield_txid not in node.getrawmempool()
        self._broadcast_wallet_tx(churn_wallet, node, churn_shield_txid)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.generatetoaddress(node, 101, mine_addr, sync_fun=self.no_op)
        stale_anchor_hex = wallet.gettransaction(stale_anchor_txid)["hex"]
        assert_raises_rpc_error(-26, "bad-shielded-anchor", node.sendrawtransaction, stale_anchor_hex)


if __name__ == "__main__":
    WalletShieldedAnchorWindowTest(__file__).main()
