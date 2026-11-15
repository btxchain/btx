#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""prepareexternalsign prepares the package it is given.

doc/integrations/external-sign.md has the coordinator build an unsigned
transaction with createexchangebatch or createconsolidationtx and pass it to
prepareexternalsign. The BTXPSBT package those RPCs return also carries
"outputs" and "recipients", and prepareexternalsign took any object with those
keys as a payment to fund again, with fresh coin selection and the default fee.
It must return the transaction it was given, with the same digests.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBCP1PreparePackageTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def unsigned(self, package):
        """(txid, digests) of a BCP/1 package."""
        txid = self.nodes[0].decoderawtransaction(package["unsigned_tx_hex"])["txid"]
        return txid, [d["digest"] for d in package["digests"]]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        miner = node.get_wallet_rpc("miner")
        node.createwallet("source")
        source = node.get_wallet_rpc("source")
        self.generatetoaddress(node, 110, miner.getnewaddress(), sync_fun=self.no_op)

        node.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        venue = node.get_wallet_rpc("venue")
        entries = []
        deposits = []
        for index in range(5):
            pubkey = source.getaddressinfo(source.getnewaddress())["pubkey"]
            address = node.deriveaddresses(f"mr({pubkey})", None, {"require_checksum": False})[0]
            # index 0 of the change branch is the omnibus; deposits 1..4 are funded.
            entries.append({"pubkey": pubkey, "index": index, "branch": 1 if index == 0 else 0})
            if index:
                deposits.append(address)
        venue.importdepositpool(entries)
        for address in deposits:
            miner.sendtoaddress(address, Decimal("2"))
        self.generatetoaddress(node, 1, miner.getnewaddress(), sync_fun=self.no_op)

        self.log.info("A withdrawal batch is prepared as built")
        payouts = [{"address": miner.getnewaddress(), "amount": 1}, {"address": miner.getnewaddress(), "amount": 1.5}]
        batch = venue.createexchangebatch(payouts, {"fee_rate": 25})
        built = self.unsigned(batch)
        assert_equal(self.unsigned(venue.prepareexternalsign(batch)), built)
        assert_equal(self.unsigned(venue.prepareexternalsign({"package": batch})), built)
        assert_equal(self.unsigned(venue.prepareexternalsign(batch["psbt"])), built)
        assert_equal([d["digest"] for d in venue.getsigningdigests(batch)["digests"]], built[1])

        self.log.info("A consolidation is prepared as built")
        consolidation = venue.createconsolidationtx({"min_confirmations": 1})
        assert_equal(self.unsigned(venue.prepareexternalsign(consolidation)), self.unsigned(consolidation))


if __name__ == '__main__':
    WalletBCP1PreparePackageTest(__file__).main()
