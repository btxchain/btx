#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test P2MR witness-clone stability, reorg handling, and wallet accounting."""

from unittest import SkipTest

from test_framework.blocktools import REGTEST_INITIAL_SUBSIDY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.messages import (
    COIN,
    tx_from_hex,
)


class TxnMallTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if self.options.segwit:
            raise SkipTest("The native P2MR variants cover witness transaction-id stability; the Bitcoin SegWit fixture is unsupported")

    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--mineblock", dest="mine_block", default=False, action="store_true",
                            help="Test double-spend of 1-confirmed transaction")
        parser.add_argument("--segwit", dest="segwit", default=False, action="store_true",
                            help="Bitcoin-only SegWit fixture (unsupported by the P2MR-only wallet policy)")

    def setup_network(self):
        # Start with split network:
        super().setup_network()
        self.disconnect_nodes(1, 2)

    def spend_utxo(self, utxo, outputs):
        inputs = [utxo]
        tx = self.nodes[0].createrawtransaction(inputs, outputs)
        tx = self.nodes[0].fundrawtransaction(tx)
        tx = self.nodes[0].signrawtransactionwithwallet(tx['hex'])
        return self.nodes[0].sendrawtransaction(tx['hex'])

    def run_test(self):
        # BTX's native P2MR spends always carry signatures in witness data.
        output_type = "p2mr"

        starting_balance = 25 * REGTEST_INITIAL_SUBSIDY
        for i in range(3):
            assert_equal(self.nodes[i].getbalance(), starting_balance)

        self.nodes[0].settxfee(.001)

        node0_address1 = self.nodes[0].getnewaddress(address_type=output_type)
        node0_utxo1 = self.create_outpoints(self.nodes[0], outputs=[{node0_address1: starting_balance - 31}])[0]
        node0_tx1 = self.nodes[0].gettransaction(node0_utxo1['txid'])
        self.nodes[0].lockunspent(False, [node0_utxo1])

        node0_address2 = self.nodes[0].getnewaddress(address_type=output_type)
        node0_utxo2 = self.create_outpoints(self.nodes[0], outputs=[{node0_address2: 29}])[0]
        node0_tx2 = self.nodes[0].gettransaction(node0_utxo2['txid'])

        assert_equal(self.nodes[0].getbalance(),
                     starting_balance + node0_tx1["fee"] + node0_tx2["fee"])

        # Coins are sent to node1_address
        node1_address = self.nodes[1].getnewaddress()

        # Send tx1, and another transaction tx2 that won't be cloned
        txid1 = self.spend_utxo(node0_utxo1, {node1_address: 40})
        txid2 = self.spend_utxo(node0_utxo2, {node1_address: 20})

        # Construct a clone of tx1, to be malleated
        rawtx1 = self.nodes[0].getrawtransaction(txid1, 1)
        clone_inputs = [{"txid": rawtx1["vin"][0]["txid"], "vout": rawtx1["vin"][0]["vout"], "sequence": rawtx1["vin"][0]["sequence"]}]
        clone_outputs = {rawtx1["vout"][0]["scriptPubKey"]["address"]: rawtx1["vout"][0]["value"],
                         rawtx1["vout"][1]["scriptPubKey"]["address"]: rawtx1["vout"][1]["value"]}
        clone_locktime = rawtx1["locktime"]
        clone_raw = self.nodes[0].createrawtransaction(clone_inputs, clone_outputs, clone_locktime)

        # createrawtransaction randomizes the order of its outputs, so swap them if necessary.
        clone_tx = tx_from_hex(clone_raw)
        if (rawtx1["vout"][0]["value"] == 40 and clone_tx.vout[0].nValue != 40*COIN or rawtx1["vout"][0]["value"] != 40 and clone_tx.vout[0].nValue == 40*COIN):
            (clone_tx.vout[0], clone_tx.vout[1]) = (clone_tx.vout[1], clone_tx.vout[0])

        # Use a different signature hash type to create another valid witness
        # for the exact same transaction. P2MR signatures live in witness data,
        # so the clone must keep its txid while changing its witness transaction
        # id. Do not send the clone anywhere yet.
        tx1_clone = self.nodes[0].signrawtransactionwithwallet(clone_tx.serialize().hex(), None, "ALL|ANYONECANPAY")
        assert_equal(tx1_clone["complete"], True)
        original_tx = tx_from_hex(self.nodes[0].gettransaction(txid1)["hex"])
        clone_tx = tx_from_hex(tx1_clone["hex"])
        assert_equal(original_tx.rehash(), clone_tx.rehash())
        assert original_tx.getwtxid() != clone_tx.getwtxid()

        # Have node0 mine a block, if requested:
        if (self.options.mine_block):
            self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_blocks(self.nodes[0:2]))

        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)

        # Node0's balance should be starting balance, plus another subsidy
        # matured block, minus tx1 and tx2 amounts, and minus transaction fees:
        expected = starting_balance + node0_tx1["fee"] + node0_tx2["fee"]
        if self.options.mine_block:
            expected += REGTEST_INITIAL_SUBSIDY
        expected += tx1["amount"] + tx1["fee"]
        expected += tx2["amount"] + tx2["fee"]
        assert_equal(self.nodes[0].getbalance(), expected)

        if self.options.mine_block:
            assert_equal(tx1["confirmations"], 1)
            assert_equal(tx2["confirmations"], 1)
        else:
            assert_equal(tx1["confirmations"], 0)
            assert_equal(tx2["confirmations"], 0)

        # Send clone and its parent to miner
        self.nodes[2].sendrawtransaction(node0_tx1["hex"])
        txid1_clone = self.nodes[2].sendrawtransaction(tx1_clone["hex"])
        assert_equal(txid1, txid1_clone)

        # Mine the alternate witness on the competing branch. Unlike the old
        # scriptSig-malleability fixture this is not a distinct txid conflict;
        # it is the same transaction confirmed with different witness bytes.
        self.generate(self.nodes[2], 1, sync_fun=self.no_op)

        # Extend the competing branch with the independent tx2, reconnect it,
        # and require node0's wallet to account for the winning P2MR clone as
        # its original transaction. wallet_txn_doublespend.py separately covers
        # distinct-txid conflict accounting.
        # Submit while the branches are still isolated. Reconnecting first
        # creates a relay race in which node2 may already know tx2 before the
        # explicit submission, turning this wallet assertion into an
        # intermittent RPC "already in UTXO set" failure.
        self.nodes[2].sendrawtransaction(node0_tx2["hex"])
        self.nodes[2].sendrawtransaction(tx2["hex"])
        # Finish the winning branch before reconnecting. In the --mineblock
        # variant the branches are otherwise equal-work and node2 can switch
        # tips while generatetoaddress is solving, making its candidate stale.
        self.generate(self.nodes[2], 1, sync_fun=self.no_op)
        self.connect_nodes(1, 2)
        self.sync_blocks()

        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)
        assert_equal(tx1["confirmations"], 2)
        assert_equal(tx2["confirmations"], 1)

        # The winning branch contributed two subsidies. If node0 mined a block
        # before the split, that block was orphaned and its subsidy must not be
        # counted twice.
        expected += 2 * REGTEST_INITIAL_SUBSIDY
        if self.options.mine_block:
            expected -= REGTEST_INITIAL_SUBSIDY
        assert_equal(self.nodes[0].getbalance(), expected)


if __name__ == '__main__':
    TxnMallTest(__file__).main()
