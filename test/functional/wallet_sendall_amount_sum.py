#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that sendall refuses specified amounts whose sum is out of range.

sendall checks each specified amount, then adds them up. Many amounts that are
each in range can pass the range of CAmount. The call must be refused like any
other request for more than the inputs hold, no transaction may be stored, and
the wallet must keep working.
"""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY, REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

MAX_MONEY = 21000000 * COIN
TOO_MUCH = "Assigned more value to outputs than available funds."


class WalletSendallAmountSumTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-fallbackfee=0.0002", "-modelnet=0"] + REGTEST_GENERIC_P2P_MATMUL_ARGS]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.generatetoaddress(node, COINBASE_MATURITY + 10, wallet.getnewaddress(address_type="p2mr"))
        node.createwallet("dest")
        dest = node.get_wallet_rpc("dest")
        remainder_addr = dest.getnewaddress(address_type="p2mr")
        max_amount = Decimal(MAX_MONEY) / COIN
        balance = wallet.getbalances()["mine"]["trusted"]
        unspent = len(wallet.listunspent())
        txs = len(wallet.listtransactions("*", 1000))

        self.log.info("Specified amounts above the balance are refused (unchanged)")
        outs = [{dest.getnewaddress(address_type="p2mr"): max_amount} for _ in range(2)]
        assert_raises_rpc_error(-6, TOO_MUCH, wallet.sendall, [remainder_addr] + outs)

        self.log.info("Specified amounts whose sum passes the range of CAmount are refused")
        count = 2**63 // MAX_MONEY + 1
        outs = [{dest.getnewaddress(address_type="p2mr"): max_amount} for _ in range(count)]
        assert_raises_rpc_error(-6, TOO_MUCH, wallet.sendall, [remainder_addr] + outs)

        self.log.info("No transaction was stored and the wallet still works")
        assert_equal(wallet.getbalances()["mine"]["trusted"], balance)
        assert_equal(len(wallet.listunspent()), unspent)
        assert_equal(len(wallet.listtransactions("*", 1000)), txs)
        self.restart_node(0)
        if self.default_wallet_name not in node.listwallets():
            node.loadwallet(self.default_wallet_name)
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        assert_equal(wallet.getbalances()["mine"]["trusted"], balance)

        self.log.info("sendall with amounts in range still works")
        txid = wallet.sendall([remainder_addr])["txid"]
        assert txid in node.getrawmempool()


if __name__ == '__main__':
    WalletSendallAmountSumTest(__file__).main()
