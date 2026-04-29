#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Live wallet-funded v2_rebalance operator flow coverage."""

from decimal import Decimal

from test_framework.bridge_utils import bridge_hex, create_bridge_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class WalletBridgeRebalanceTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        def assert_redacted_family(obj):
            assert_equal(obj["family"], "shielded_v2")
            assert obj["family_redacted"]

        node = self.nodes[0]
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="operator", amount=Decimal("6"))

        reserve_addr_a = wallet.z_getnewaddress()
        reserve_addr_b = wallet.z_getnewaddress()

        self.log.info("Reject non-canonical reserve delta sets before publish")
        assert_raises_rpc_error(
            -8,
            "reserve_deltas must be canonical, unique, and zero-sum",
            wallet.bridge_submitrebalancetx,
            [
                {"l2_id": bridge_hex(0x31), "reserve_delta": Decimal("5")},
                {"l2_id": bridge_hex(0x31), "reserve_delta": Decimal("-5")},
            ],
            [],
            {},
        )

        reserve_deltas = [
            {"l2_id": bridge_hex(0x41), "reserve_delta": Decimal("7")},
            {"l2_id": bridge_hex(0x42), "reserve_delta": Decimal("-4")},
            {"l2_id": bridge_hex(0x43), "reserve_delta": Decimal("-3")},
        ]
        reserve_outputs = [
            {"address": reserve_addr_a, "amount": Decimal("3")},
            {"address": reserve_addr_b, "amount": Decimal("4")},
        ]
        options = {
            "settlement_window": 288,
            "gross_flow_commitment": bridge_hex(0x91),
            "authorization_digest": bridge_hex(0x92),
        }

        self.log.info("Publish a live multi-domain v2_rebalance from wallet funds")
        result = wallet.bridge_submitrebalancetx(reserve_deltas, reserve_outputs, options)
        assert_redacted_family(result)
        assert result["bundle_metadata_redacted"]
        for key in (
            "reserve_domain_count",
            "reserve_output_count",
            "output_chunk_count",
            "netting_manifest_id",
            "settlement_binding_digest",
            "batch_statement_digest",
        ):
            assert key not in result
        assert_greater_than(result["fee"], Decimal("0"))
        assert result["txid"] in node.getrawmempool()

        self.log.info("Wallet view should expose the reserve outputs and canonical chunk summary")
        view = wallet.z_viewtransaction(result["txid"])
        assert_redacted_family(view)
        assert_equal(len(view["outputs"]), 2)
        assert_equal(len(view["output_chunks"]), 1)
        visible_amounts = sorted(output["amount"] for output in view["outputs"] if output["is_ours"])
        assert_equal(visible_amounts, [Decimal("3"), Decimal("4")])

        self.log.info("Raw decode should expose the committed manifest and deterministic binding digests")
        decoded = node.getrawtransaction(result["txid"], True)
        shielded = decoded["shielded"]
        assert_equal(shielded["bundle_type"], "v2")
        assert_equal(shielded["family"], "v2_rebalance")
        settlement_binding_digest = shielded["payload"]["settlement_binding_digest"]
        batch_statement_digest = shielded["payload"]["batch_statement_digest"]
        assert_equal(len(shielded["payload"]["reserve_deltas"]), 3)
        assert_equal(len(shielded["payload"]["reserve_outputs"]), 2)
        manifest = shielded["payload"]["netting_manifest"]
        manifest_id = manifest["manifest_id"]
        assert_equal(manifest["settlement_window"], 288)
        assert_equal(manifest["gross_flow_commitment"], bridge_hex(0x91))
        assert_equal(manifest["authorization_digest"], bridge_hex(0x92))

        self.log.info("The rebalance should mine cleanly and retain the same manifest id on-chain")
        block_hash = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]
        mined = node.getrawtransaction(result["txid"], True, block_hash)
        assert_equal(mined["confirmations"], 1)
        assert_equal(
            mined["shielded"]["payload"]["settlement_binding_digest"],
            settlement_binding_digest,
        )
        assert_equal(
            mined["shielded"]["payload"]["batch_statement_digest"],
            batch_statement_digest,
        )
        assert_equal(
            mined["shielded"]["payload"]["netting_manifest"]["manifest_id"],
            manifest_id,
        )


if __name__ == "__main__":
    WalletBridgeRebalanceTest(__file__).main()
