#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
    unlock_wallet,
)
from test_framework.test_framework import BitcoinTestFramework


class WalletShieldedReorgRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0, n1 = self.nodes
        n0.createwallet(wallet_name="w0", descriptors=True)
        n1.createwallet(wallet_name="w1", descriptors=True)
        w0 = encrypt_and_unlock_wallet(n0, "w0")
        w1 = encrypt_and_unlock_wallet(n1, "w1")

        self.log.info("Build initial shared chain and create a confirmed shielded note")
        mine0 = w0.getnewaddress()
        fund_trusted_transparent_balance(
            self, n0, w0, mine0, Decimal("10.0"), sync_fun=self.sync_all
        )
        z0 = w0.z_getnewaddress()
        w0.z_shieldfunds(Decimal("2.0"), z0)
        self.generatetoaddress(n0, 1, mine0, sync_fun=self.sync_all)
        ensure_ring_diversity(
            self,
            n0,
            w0,
            mine0,
            z0,
            min_notes=16,
            topup_amount=Decimal("0.25"),
            sync_fun=self.sync_all,
        )
        confirmed_balance = Decimal(w0.z_getbalance()["balance"])
        assert confirmed_balance > Decimal("1.0")

        self.log.info("Fork chains, confirm a shielded spend only on node0, and outgrow it on node1")
        self.disconnect_nodes(0, 1)
        z1 = w0.z_getnewaddress()
        tx_reorged = w0.z_sendmany([{"address": z1, "amount": Decimal("1.0")}])["txid"]
        self.generatetoaddress(n0, 1, mine0, sync_fun=self.no_op)
        pre_reorg_tip = n0.getbestblockhash()

        mine1 = w1.getnewaddress()
        self.generatetoaddress(n1, 2, mine1, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, n1])
        assert n0.getbestblockhash() != pre_reorg_tip

        self.log.info("Clear mempool and verify wallet can spend shielded funds again after reorg rollback")
        self.restart_node(0, extra_args=["-persistmempool=0", "-walletbroadcast=0"])
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, n1])
        if "w0" not in n0.listwallets():
            n0.loadwallet("w0")
        w0 = unlock_wallet(n0, "w0")

        # Reorged transaction should no longer be confirmed.
        tx_status = w0.gettransaction(tx_reorged)
        assert tx_status["confirmations"] <= 0

        post_reorg_balance = Decimal(w0.z_getbalance()["balance"])
        assert post_reorg_balance > Decimal("1.0")
        z2 = w0.z_getnewaddress()
        send_res = w0.z_sendmany([{"address": z2, "amount": Decimal("0.1")}])
        txid = send_res["txid"]
        tx_hex = w0.gettransaction(txid)["hex"]
        accept = n0.testmempoolaccept([tx_hex])[0]
        assert accept["allowed"]
        n0.sendrawtransaction(tx_hex)
        assert txid in n0.getrawmempool()


if __name__ == "__main__":
    WalletShieldedReorgRecoveryTest(__file__).main()
