#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the error that funding RPCs return on a locked wallet.

A locked wallet holds no PQ seeds, so it cannot size its own P2MR coins and
coin selection leaves them out, while getbalances still counts them as
trusted. send, walletcreatefundedpsbt and fundrawtransaction must then ask
for the passphrase (-13) instead of reporting "Insufficient funds" (-4).
A real shortfall keeps its -4.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

PASSPHRASE = "passphrase"
UNLOCK_NEEDED = "Please enter the wallet passphrase with walletpassphrase first."


class WalletLockedFundingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-modelnet=0",
            "-modelbind=off",
            # Regtest-only MatMul knobs that keep block generation fast.
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        funder = node.get_wallet_rpc("funder")
        self.generatetoaddress(node, 110, funder.getnewaddress(), sync_fun=self.no_op)
        dest = funder.getnewaddress()

        node.createwallet(wallet_name="locked", descriptors=True, passphrase=PASSPHRASE)
        wallet = node.get_wallet_rpc("locked")
        funder.sendtoaddress(wallet.getnewaddress(), 5)
        self.generatetoaddress(node, 1, dest, sync_fun=self.no_op)
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)

        self.log.info("A locked wallet counts its coins as trusted but cannot use them")
        assert_equal(wallet.getbalances()["mine"]["trusted"], Decimal("5"))
        [coin] = wallet.listunspent()
        assert_equal((coin["spendable"], coin["solvable"]), (False, False))

        self.log.info("Funding RPCs ask for the passphrase")
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.send, [{dest: 1}])
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.walletcreatefundedpsbt, [], [{dest: 1}])
        raw = wallet.createrawtransaction([], [{dest: 1}])
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.fundrawtransaction, raw)
        # The same with the coin preselected, which used to say "Not solvable pre-selected input".
        preselected = wallet.createrawtransaction([{"txid": coin["txid"], "vout": coin["vout"]}], [{dest: 1}])
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.fundrawtransaction, preselected)

        self.log.info("Errors that unlocking cannot fix keep their own answer on the locked wallet")
        assert_raises_rpc_error(-4, "is lower than the minimum fee rate setting", wallet.send, [{dest: 1}], fee_rate=0.1)
        assert_raises_rpc_error(-4, "Transaction amount too small", wallet.walletcreatefundedpsbt, [], [{dest: Decimal("0.00000001")}])
        tiny = wallet.createrawtransaction([], [{dest: Decimal("0.00000001")}])
        assert_raises_rpc_error(-4, "Transaction amount too small", wallet.fundrawtransaction, tiny)

        self.log.info("A locked wallet with no coins of its own still reports the shortfall")
        node.createwallet(wallet_name="empty", descriptors=True, passphrase=PASSPHRASE)
        empty = node.get_wallet_rpc("empty")
        assert_raises_rpc_error(-4, "Insufficient funds", empty.walletcreatefundedpsbt, [], [{dest: 1}])

        self.log.info("Once unlocked, the wallet funds, and a real shortfall is still -4")
        wallet.walletpassphrase(PASSPHRASE, 600)
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.walletcreatefundedpsbt, [], [{dest: 10}])
        wallet.walletcreatefundedpsbt([], [{dest: 1}])
        wallet.fundrawtransaction(raw)
        result = wallet.send([{dest: 1}])
        assert result["complete"]
        assert result["txid"] in node.getrawmempool()


if __name__ == "__main__":
    WalletLockedFundingTest(__file__).main()
