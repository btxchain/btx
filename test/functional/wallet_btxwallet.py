#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise first-class .btxwallet restore/import support."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBtxWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def write_bundle(self, name, **overrides):
        bundle = {
            "format": "btx-wallet-bundle",
            "version": 1,
            "network": "regtest",
            "pq_master_seed": "11" * 32,
            "coin_type": 1,
            "account": 0,
            "birthday": 1,
            "algorithms": ["ml-dsa-44", "slh-dsa-128s"],
        }
        bundle.update(overrides)
        path = self.nodes[0].datadir_path / name
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return path

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Restore a new wallet from a minimal browser .btxwallet file")
        bundle_path = self.write_bundle("browser-wallet.btxwallet.json")
        restored = node.restorewalletbundle("from-btxwallet", bundle_path, None, False)
        assert_equal(restored["success"], True)
        assert_equal(restored["network"], "regtest")
        assert_equal(restored["descriptors_imported"], 2)
        assert restored["first_receive_address"].startswith("btxrt1")

        wallet = node.get_wallet_rpc("from-btxwallet")
        assert_equal(wallet.getnewaddress(), restored["first_receive_address"])

        self.log.info("Import the same bundle into an existing blank descriptor wallet")
        node.createwallet(wallet_name="blank-target", descriptors=True, blank=True)
        blank = node.get_wallet_rpc("blank-target")
        imported = blank.importwalletbundle(bundle_path, False)
        assert_equal(imported["success"], True)
        assert_equal(imported["first_receive_address"], restored["first_receive_address"])
        assert_equal(blank.getnewaddress(), restored["first_receive_address"])

        self.log.info("Reject bundles whose claimed first address does not match the seed")
        mismatch_path = self.write_bundle(
            "mismatched.btxwallet.json",
            first_receive_address="btxrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        )
        assert_raises_rpc_error(
            -8,
            "first_receive_address does not match pq_master_seed",
            node.restorewalletbundle,
            "bad-first-address",
            mismatch_path,
            None,
            False,
        )

        self.log.info("Reject bundles whose descriptor strings do not match the seed")
        descriptor_mismatch_path = self.write_bundle(
            "mismatched-descriptor.btxwallet.json",
            descriptors=[
                "mr(pqhd(00112233/0h/0h/0/*),pk_slh(pqhd(00112233/0h/0h/0/*)))#wrong",
                "mr(pqhd(00112233/0h/0h/1/*),pk_slh(pqhd(00112233/0h/0h/1/*)))#wrong",
            ],
        )
        assert_raises_rpc_error(
            -8,
            "descriptors do not match pq_master_seed/network/account",
            node.restorewalletbundle,
            "bad-descriptor",
            descriptor_mismatch_path,
            None,
            False,
        )

        self.log.info("Reject bundles for the wrong chain")
        wrong_network_path = self.write_bundle("wrong-network.btxwallet.json", network="main", coin_type=0)
        assert_raises_rpc_error(
            -8,
            "does not match current chain",
            node.restorewalletbundle,
            "bad-network",
            wrong_network_path,
            None,
            False,
        )


if __name__ == "__main__":
    WalletBtxWalletTest(__file__).main()
