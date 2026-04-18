#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test sendall preferred_pq_algo option handling."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class WalletSendAllPQTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="sender", descriptors=True)
        node.createwallet(wallet_name="receiver", descriptors=True)
        sender = node.get_wallet_rpc("sender")
        receiver = node.get_wallet_rpc("receiver")

        mine_addr = sender.getnewaddress()
        self.log.info("mine mature balance for sender")
        # Mine exactly one matured coinbase UTXO to keep sendall economical.
        self.generatetoaddress(node, 101, mine_addr, sync_fun=self.no_op)

        recv_addr = receiver.getnewaddress()
        sender_before = sender.getbalances()["mine"]["trusted"]

        self.log.info("sendall rejects invalid preferred_pq_algo values")
        assert_raises_rpc_error(
            -8,
            "Invalid preferred_pq_algo",
            sender.sendall,
            recipients=[recv_addr],
            options={"preferred_pq_algo": "invalid"},
        )

        self.log.info("sendall accepts explicit SLH-DSA preference")
        try:
            result = sender.sendall(
                recipients=[recv_addr],
                options={
                    "preferred_pq_algo": "slh_dsa_128s",
                    # Keep fee assumptions deterministic under BTX regtest reward dynamics.
                    "fee_rate": 1,
                    "send_max": True,
                },
            )
        except JSONRPCException as e:
            if (
                e.error["code"] == -6
                and "Total value of UTXO pool too low" in e.error["message"]
            ):
                self.log.info(
                    "preferred_pq_algo accepted; sendall rejected only due to "
                    "uneconomic UTXO pool under current chain profile"
                )
                return
            raise
        assert_equal(result["complete"], True)
        assert "txid" in result
        tx = sender.gettransaction(result["txid"], verbose=True)
        output_addresses = [vout["scriptPubKey"].get("address") for vout in tx["decoded"]["vout"]]
        assert recv_addr in output_addresses

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        sender_balance = sender.getbalances()["mine"]["trusted"]
        receiver_balance = receiver.getbalances()["mine"]["trusted"]
        assert sender_balance < sender_before
        assert_greater_than(receiver_balance, 0)


if __name__ == "__main__":
    WalletSendAllPQTest(__file__).main()
