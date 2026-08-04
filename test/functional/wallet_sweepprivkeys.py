#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the sweepprivkeys RPC."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_fee_amount

class SweepPrivKeysTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        # sweepprivkeys is a compatibility RPC for legacy WIF/P2PKH funds.
        # Permit its nonstandard fixture on regtest without changing BTX's
        # production P2MR-only relay policy.
        self.extra_args = [["-acceptnonstdtxn=1"], ["-acceptnonstdtxn=1"]]

    def check_balance(self, delta, txid):
        node = self.nodes[0]
        new_balances = node.getbalances()['mine']
        new_balance = new_balances['trusted'] + new_balances['untrusted_pending']
        balance_change = new_balance - self.balance
        wallet_tx = node.gettransaction(txid)
        actual_fee = node.getmempoolentry(txid)['fees']['base']
        assert_equal(balance_change, Decimal(delta) - actual_fee)
        # Once mined, getrawtransaction requires -txindex.  The wallet keeps
        # the raw transaction needed for an exact vsize calculation.
        tx_vsize = node.decoderawtransaction(wallet_tx['hex'])['vsize']
        assert_fee_amount(actual_fee, tx_vsize, self.tx_feerate)
        self.balance = new_balance

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        miner = self.nodes[1]

        keys = (
            ('mkckmmfVv89sW1HUjyRuydGhwFmSaYtRvG', '92YkaycAxLPUqbbV78V9nNngKLnyVd9T8uZuZAzQnc26dJSP4fm'),
            ('mw8s1FS2Vr7GwQF8bnDVUQHQZq5qWqz5kq', '93VijJgAYnVUGXAfxYhbMHVGVwQUEXK1YnPvcCod3x1RLbzUhXe'),
        )

        # This test is not meant to test fee estimation and we'd like
        # to be sure all txs are sent at a consistent desired feerate
        self.tx_feerate = max(self.nodes[0].getnetworkinfo()['relayfee'], self.nodes[0].getwalletinfo()['mintxfee']) * 2
        node.settxfee(self.tx_feerate)

        self.generate(miner, 120)
        self.balance = node.getbalance('*', 0)

        txid = node.sendtoaddress(keys[0][0], 10)
        self.check_balance(-10, txid)

        # Sweep from mempool
        txid = node.sweepprivkeys({'privkeys': (keys[0][1],), 'label': 'test 1'})
        assert_equal(node.listtransactions()[-1]['label'], 'test 1')
        self.check_balance(10, txid)

        txid = node.sendtoaddress(keys[1][0], 5)
        self.check_balance(-5, txid)
        self.sync_all()
        self.generate(miner, 4)
        assert_equal(self.balance, node.getbalance('*', 1))

        # Sweep from blockchain
        txid = node.sweepprivkeys({'privkeys': (keys[1][1],), 'label': 'test 2'})
        assert_equal(node.listtransactions()[-1]['label'], 'test 2')
        self.check_balance(5, txid)

if __name__ == '__main__':
    SweepPrivKeysTest(__file__).main()
