#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Keep signed P2MR send previews unpublished until explicitly submitted.

Complements wallet_send's preparation assertions with a P2MR-only fixture.
The signing wallet must complete the transaction: an incomplete watch-only
PSBT would not exercise the separate PSBT opt-in publication guard.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


AMOUNT = Decimal("1")
CASES = (
    ("psbt_default", {"psbt": True}, True),
    ("psbt_explicit_add", {"psbt": True, "add_to_wallet": True}, True),
    ("no_add", {"add_to_wallet": False}, True),
    ("ordinary", {}, False),
)


class SendPSBTPreviewTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + [
            "-autoshieldcoinbase=0", "-swapnet=0", "-autoupdate=0",
            "-networkactive=0", "-dandelion=0",
        ]]

    def setup_network(self):
        if self.config["components"].getboolean("ENABLE_MODELNET", fallback=False):
            self.extra_args[0].append("-nomodelnet")
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def snapshot(self, wallet):
        return {
            "balance": wallet.getbalances()["mine"],
            "transactions": sorted({row["txid"] for row in wallet.listtransactions("*", 1000)}),
            "utxos": sorted((row["txid"], row["vout"], row["amount"], row["spendable"])
                            for row in wallet.listunspent()),
            "locks": sorted((row["txid"], row["vout"]) for row in wallet.listlockunspent()),
        }

    def check_transaction(self, raw, txid, coin, recipient_script, change_script):
        decoded = self.nodes[0].decoderawtransaction(raw)
        assert_equal(decoded["txid"], txid)
        assert_equal(len(decoded["vin"]), 1)
        assert_equal((decoded["vin"][0]["txid"], decoded["vin"][0]["vout"]),
                     (coin["txid"], coin["vout"]))
        assert_equal(len(decoded["vout"]), 2)
        outputs = {row["scriptPubKey"]["hex"]: row["value"] for row in decoded["vout"]}
        assert_equal(set(outputs), {recipient_script, change_script})
        assert_equal(outputs[recipient_script], AMOUNT)
        assert_greater_than(outputs[change_script], 0)
        fee = coin["amount"] - sum(row["value"] for row in decoded["vout"])
        assert_greater_than(fee, 0)
        return fee

    def check_case(self, name, flags, preview, sender, receiver, mining_address):
        node = self.nodes[0]
        coins = sender.listunspent()
        assert_equal(len(coins), 1)
        coin = coins[0]
        assert_equal(coin["spendable"], True)
        assert_equal(coin["solvable"], True)
        assert_greater_than(coin["confirmations"], 100)
        assert_greater_than(coin["amount"], AMOUNT + Decimal("0.01"))
        destination = receiver.getnewaddress()
        change = sender.getrawchangeaddress()
        assert destination.startswith("btxrt1z")
        assert change.startswith("btxrt1z")
        recipient_script = receiver.getaddressinfo(destination)["scriptPubKey"]
        change_script = sender.getaddressinfo(change)["scriptPubKey"]
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getrawmempool(), [])
        before_sender, before_receiver = self.snapshot(sender), self.snapshot(receiver)
        before_coin = node.gettxout(coin["txid"], coin["vout"], True)
        assert_equal(before_coin["value"], coin["amount"])
        options = {
            "inputs": [{"txid": coin["txid"], "vout": coin["vout"]}],
            "add_inputs": False, "change_address": change, "fee_rate": 2,
            **flags,
        }
        result = sender.send(outputs=[{destination: AMOUNT}], options=options)
        assert_equal(result["complete"], True)
        txid = result["txid"]
        if preview:
            raw = result["hex"]
            finalized = node.finalizepsbt(result["psbt"])
            assert_equal(finalized["complete"], True)
            assert_equal(finalized["hex"], raw)
            fee = self.check_transaction(raw, txid, coin, recipient_script, change_script)
            admission = node.testmempoolaccept([raw])
            assert_equal(len(admission), 1)
            assert_equal(admission[0]["allowed"], True)
            node.syncwithvalidationinterfacequeue()
            assert_equal(node.getrawmempool(), [])
            assert_equal(self.snapshot(sender), before_sender)
            assert_equal(self.snapshot(receiver), before_receiver)
            assert_equal(node.gettxout(coin["txid"], coin["vout"], True), before_coin)
            for wallet in (sender, receiver):
                assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", wallet.gettransaction, txid)
            self.log.info("%s: complete payment remains unpublished", name)
            assert_equal(node.sendrawtransaction(raw), txid)
        else:
            assert "hex" not in result
            assert "psbt" not in result
            node.syncwithvalidationinterfacequeue()
            raw = sender.gettransaction(txid)["hex"]
            fee = self.check_transaction(raw, txid, coin, recipient_script, change_script)

        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getrawmempool(), [txid])
        assert_equal(node.gettxout(coin["txid"], coin["vout"], True), None)
        self.log.info("%s: exact payment published", name)
        block = self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)[0]
        node.syncwithvalidationinterfacequeue()
        assert txid in node.getblock(block)["tx"]
        assert_equal(node.getrawmempool(), [])
        for wallet in (sender, receiver):
            confirmed = wallet.gettransaction(txid)
            assert_equal(confirmed["blockhash"], block)
            assert_equal(confirmed["confirmations"], 1)
        assert_equal(-sender.gettransaction(txid)["fee"], fee)
        assert_equal(receiver.getbalances()["mine"]["trusted"],
                     before_receiver["balance"]["trusted"] + AMOUNT)
        assert_equal(sender.getbalances()["mine"]["trusted"],
                     before_sender["balance"]["trusted"] - AMOUNT - fee)
        assert_equal(node.gettxout(coin["txid"], coin["vout"], False), None)
        self.log.info("%s: exact payment confirmed with expected balances", name)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner", descriptors=True)
        node.createwallet("receiver", descriptors=True)
        mining_address = node.get_wallet_rpc("miner").getnewaddress()
        receiver = node.get_wallet_rpc("receiver")
        senders = []
        for name, _flags, _preview in CASES:
            node.createwallet(name, descriptors=True)
            sender = node.get_wallet_rpc(name)
            assert_equal(sender.getwalletinfo()["private_keys_enabled"], True)
            address = sender.getnewaddress()
            assert address.startswith("btxrt1z")
            self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
            senders.append(sender)
        self.generatetoaddress(node, 100, mining_address, sync_fun=self.no_op)
        node.syncwithvalidationinterfacequeue()
        for (name, flags, preview), sender in zip(CASES, senders):
            self.check_case(name, flags, preview, sender, receiver, mining_address)


if __name__ == '__main__':
    SendPSBTPreviewTest(__file__).main()
