#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test z_verifywalletintegrity classification for PQ signer wallets."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletVerifyWalletIntegrityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        signer_wallets = []
        pq_keys = []

        self.log.info("Create 3 signer wallets and export one deterministic PQ key from each")
        for idx in range(3):
            name = f"signer_{idx}"
            node.createwallet(wallet_name=name, descriptors=True)
            wallet = node.get_wallet_rpc(name)
            signer_wallets.append(wallet)

            address = wallet.getnewaddress(address_type="p2mr")
            exported = wallet.exportpqkey(address, "ml-dsa-44")
            pq_keys.append(exported["key"])

        self.log.info("Import the same fixed-key PQ multisig descriptor into every signer wallet")
        for wallet in signer_wallets:
            added = wallet.addpqmultisigaddress(2, pq_keys, "team-signer", True)
            assert "sortedmulti_pq(" in added["descriptor"]

        self.log.info("Imported public-only multisig descriptors should not fail integrity")
        for wallet in signer_wallets:
            report = wallet.z_verifywalletintegrity()
            assert_equal(report["integrity_ok"], True)
            assert_equal(report["pq_descriptors"], 3)
            assert_equal(report["pq_descriptors_with_seed"], 2)
            assert_equal(report["pq_seed_capable_descriptors"], 2)
            assert_equal(report["pq_seed_capable_with_seed"], 2)
            assert_equal(report["pq_public_only_descriptors"], 1)
            assert_equal(report["warnings"], [])
            assert_equal(len(report["notes"]), 1)
            assert "public-only" in report["notes"][0]


if __name__ == "__main__":
    WalletVerifyWalletIntegrityTest(__file__).main()
