#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Focused postfork v2_egress_batch wallet build coverage."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_egress_batch_tx,
    build_egress_statement,
    build_proof_policy,
    build_proof_profile,
    build_proof_receipt,
    create_bridge_wallet,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeEgressBuildTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-regtestshieldedmatrictdisableheight=110"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        wallet, _ = create_bridge_wallet(self, node, wallet_name="egress_build")
        assert node.getblockcount() < 110

        def build_case():
            recipients = [
                {"address": wallet.z_getnewaddress(), "amount": Decimal("0.11")},
                {"address": wallet.z_getnewaddress(), "amount": Decimal("0.12")},
            ]

            proof_profile = build_proof_profile(
                wallet,
                family="bridge",
                proof_type="groth16",
                claim_system="receipt",
            )
            descriptor = {
                "proof_system_id": proof_profile["proof_system_id"],
                "verifier_key_hash": bridge_hex(0x91),
            }
            proof_policy = build_proof_policy(wallet, [descriptor], required_receipts=1, targets=[descriptor])
            statement = build_egress_statement(
                wallet,
                recipients,
                bridge_id=bridge_hex(0x81),
                operation_id=bridge_hex(0x82),
                domain_id=bridge_hex(0x83),
                source_epoch=9,
                data_root=bridge_hex(0x84),
                proof_policy=proof_policy["proof_policy"],
            )
            proof_receipt = build_proof_receipt(
                wallet,
                statement["statement_hex"],
                proof_profile_hex=proof_profile["profile_hex"],
                verifier_key_hash=descriptor["verifier_key_hash"],
                public_values_hash=bridge_hex(0x85),
                proof_commitment=bridge_hex(0x86),
            )

            built = build_egress_batch_tx(
                wallet,
                statement["statement_hex"],
                [descriptor],
                [proof_receipt["proof_receipt_hex"]],
                recipients,
            )
            return built, statement

        self.log.info("Build a prefork proof-policy egress batch through the wallet RPC")
        prefork_built, prefork_statement = build_case()
        assert_equal(prefork_built["family"], "v2_egress_batch")
        assert_equal(prefork_built["statement_hash"], prefork_statement["statement_hash"])
        assert_equal(len(prefork_built["outputs"]), 2)
        assert_equal(len(prefork_built["output_chunks"]), 1)
        assert_equal(prefork_built["output_chunks"][0]["first_output_index"], 0)
        assert_equal(prefork_built["output_chunks"][0]["output_count"], 2)
        prefork_decoded = node.decoderawtransaction(prefork_built["tx_hex"])
        assert_equal(prefork_decoded["shielded"]["family"], "v2_egress_batch")

        self.log.info("Advance to the postfork boundary and confirm wallet-visible family redaction")
        mine_addr = wallet.getnewaddress(address_type="p2mr")
        self.generatetoaddress(node, max(0, 110 - node.getblockcount()), mine_addr, sync_fun=self.no_op)
        assert node.getblockcount() >= 110

        postfork_built, postfork_statement = build_case()
        assert_equal(postfork_built["family"], "shielded_v2")
        assert_equal(postfork_built["statement_hash"], postfork_statement["statement_hash"])
        assert_equal(len(postfork_built["outputs"]), 2)
        assert_equal(len(postfork_built["output_chunks"]), 1)
        assert_equal(postfork_built["output_chunks"][0]["first_output_index"], 0)
        assert_equal(postfork_built["output_chunks"][0]["output_count"], 2)
        postfork_decoded = node.decoderawtransaction(postfork_built["tx_hex"])
        assert_equal(postfork_decoded["shielded"]["family"], "v2_egress_batch")


if __name__ == "__main__":
    WalletBridgeEgressBuildTest(__file__).main()
