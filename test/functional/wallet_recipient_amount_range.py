#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that the wallet refuses recipient amounts outside MoneyRange.

CreateTransaction adds the recipient amounts and the coin selection works with
that sum. fundrawtransaction takes the output values of a raw transaction as
they are, and createexchangebatch accepts many outputs that are each in range.
An amount or a sum outside MoneyRange must be refused with an RPC error, and
the node must stay up.
"""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY, REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.messages import COIN, CTransaction, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

MAX_MONEY = 21000000 * COIN
OUT_OF_RANGE = "Transaction amounts out of range"


class WalletRecipientAmountRangeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-fallbackfee=0.0002", "-modelnet=0"] + REGTEST_GENERIC_P2P_MATMUL_ARGS]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def raw_with_outputs(self, script, values):
        tx = CTransaction()
        tx.vout = [CTxOut(v, script) for v in values]
        return tx.serialize().hex()

    def run_test(self):
        node = self.nodes[0]
        self.generatetoaddress(node, COINBASE_MATURITY + 3, node.getnewaddress(address_type="p2mr"))
        dest = node.getnewaddress(address_type="p2mr")
        script = bytes.fromhex(node.getaddressinfo(dest)["scriptPubKey"])

        self.log.info("fundrawtransaction refuses an output value outside MoneyRange")
        for values in ([2**62, 2**62], [2**62], [MAX_MONEY + 1]):
            assert_raises_rpc_error(-4, OUT_OF_RANGE, node.fundrawtransaction,
                                    self.raw_with_outputs(script, values), {"fee_rate": 1})
            assert_equal(node.getblockcount(), COINBASE_MATURITY + 3)

        self.log.info("fundrawtransaction refuses values whose sum is out of range")
        for values in ([MAX_MONEY, MAX_MONEY], [MAX_MONEY, 2**63 - 1]):
            assert_raises_rpc_error(-4, OUT_OF_RANGE, node.fundrawtransaction,
                                    self.raw_with_outputs(script, values), {"fee_rate": 1})
            assert_equal(node.getblockcount(), COINBASE_MATURITY + 3)

        self.log.info("createexchangebatch refuses outputs in range whose sum passes the range of CAmount")
        count = 2**63 // MAX_MONEY + 1
        outs = [{"address": dest, "amount": Decimal(MAX_MONEY) / COIN}] * count
        assert_raises_rpc_error(-4, OUT_OF_RANGE, node.createexchangebatch, outs)
        assert_equal(node.getblockcount(), COINBASE_MATURITY + 3)

        self.log.info("Amounts in range still work")
        funded = node.fundrawtransaction(self.raw_with_outputs(script, [COIN]), {"fee_rate": 1})
        assert funded["fee"] > 0
        batch = node.createexchangebatch([{"address": dest, "amount": Decimal("0.5")}])
        assert batch["selected_utxos"]


if __name__ == '__main__':
    WalletRecipientAmountRangeTest(__file__).main()
