#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the locked-wallet error of the funding RPCs that do not use FundTransaction().

A locked wallet holds no PQ seeds, so it cannot size its own P2MR coins.
sendall collects its inputs itself, createexchangebatch and
createconsolidationtx fund an unsigned BCP/1 package, and z_planshieldfunds
builds signed candidate chunks. On a locked wallet that holds coins of its own
they must ask for the passphrase (-13), as wallet_locked_funding.py checks for
send, walletcreatefundedpsbt and fundrawtransaction. A locked wallet without
coins keeps its shortfall error, and once unlocked the same requests work.
The wallet's coin is a mature coinbase output, because after the fork direct
transparent shielding takes only those.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

PASSPHRASE = "passphrase"
UNLOCK_NEEDED = "Please enter the wallet passphrase with walletpassphrase first."


class WalletLockedFundingMoreTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-fallbackfee=0.0002",
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

    def inputs_of(self, package):
        return [(i["txid"], i["vout"]) for i in self.nodes[0].decodepsbt(package["psbt"])["tx"]["vin"]]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        funder = node.get_wallet_rpc("funder")
        dest = funder.getnewaddress()
        change = funder.getnewaddress()

        node.createwallet(wallet_name="locked", descriptors=True, passphrase=PASSPHRASE)
        wallet = node.get_wallet_rpc("locked")
        wallet.walletpassphrase(PASSPHRASE, 600)
        zaddr = wallet.z_getnewaddress()
        wallet.walletlock()
        self.generatetoaddress(node, 1, wallet.getnewaddress(), sync_fun=self.no_op)
        self.generatetoaddress(node, 110, dest, sync_fun=self.no_op)
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        [coin] = wallet.listunspent()
        assert_equal((coin["spendable"], coin["solvable"]), (False, False))
        outpoint = (coin["txid"], coin["vout"])
        too_much = coin["amount"] + 1

        self.log.info("sendall asks for the passphrase, also with the coin given as input")
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.sendall, [dest])
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.sendall, recipients=[dest],
                                options={"inputs": [{"txid": coin["txid"], "vout": coin["vout"]}]})

        self.log.info("The BCP/1 package builders ask for the passphrase")
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.createexchangebatch, [{"address": dest, "amount": 1}])
        # The plan lists the coin; building the consolidation needs its size.
        assert_equal([(i["txid"], i["vout"]) for i in wallet.planconsolidation()["inputs"]], [outpoint])
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.createconsolidationtx, change)
        # An error that unlocking cannot fix keeps its own answer.
        assert_raises_rpc_error(-4, "Transaction amount too small", wallet.createexchangebatch, [{"address": dest, "amount_atoms": 1}])

        self.log.info("The shielding plan asks for the passphrase")
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, wallet.z_planshieldfunds, 1, zaddr)

        self.log.info("A locked wallet with no coins of its own still reports the shortfall")
        node.createwallet(wallet_name="empty", descriptors=True, passphrase=PASSPHRASE)
        empty = node.get_wallet_rpc("empty")
        assert_raises_rpc_error(-6, "Total value of UTXO pool too low", empty.sendall, [dest])
        assert_raises_rpc_error(-4, "Insufficient funds", empty.createexchangebatch, [{"address": dest, "amount": 1}])
        assert_raises_rpc_error(-6, "no deposit UTXOs", empty.createconsolidationtx, change)
        assert_raises_rpc_error(-6, "Insufficient transparent funds", empty.z_planshieldfunds, 1, zaddr)

        self.log.info("Once unlocked, the same requests work, and a real shortfall keeps its error")
        wallet.walletpassphrase(PASSPHRASE, 600)
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.createexchangebatch, [{"address": dest, "amount": too_much}])
        assert_raises_rpc_error(-6, "Insufficient transparent funds", wallet.z_planshieldfunds, too_much, zaddr)
        batch = wallet.createexchangebatch([{"address": dest, "amount": 1}])
        assert_equal((batch["broadcast"], batch["complete"]), (False, False))
        assert_equal(self.inputs_of(batch), [outpoint])
        consolidation = wallet.createconsolidationtx(change)
        assert_equal((consolidation["broadcast"], consolidation["complete"]), (False, False))
        assert_equal(self.inputs_of(consolidation), [outpoint])
        plan = wallet.z_planshieldfunds(1, zaddr)
        assert_equal(plan["requested_amount"], Decimal("1"))
        assert_equal(plan["estimated_chunk_count"], 1)
        result = wallet.sendall([dest])
        assert result["complete"]
        assert result["txid"] in node.getrawmempool()
        assert_equal(wallet.listunspent(), [])


if __name__ == "__main__":
    WalletLockedFundingMoreTest(__file__).main()
