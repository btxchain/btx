#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class WalletShieldedViewingKeyRescanTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0", "-regtestshieldedmatrictdisableheight=500"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="owner", descriptors=True)
        node.createwallet(wallet_name="viewer", blank=True, descriptors=True)
        node.createwallet(wallet_name="viewer_nokeys", blank=True, descriptors=True, disable_private_keys=True)
        owner = encrypt_and_unlock_wallet(node, "owner")
        viewer = encrypt_and_unlock_wallet(node, "viewer")
        viewer_nokeys = node.get_wallet_rpc("viewer_nokeys")

        self.log.info("Fund transparent balance, shield it, and seed enough notes for v2_send recovery coverage")
        mine_addr = owner.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, owner, mine_addr, Decimal("6.0"), sync_fun=self.no_op
        )

        z_funding = owner.z_getnewaddress()
        shield_res = owner.z_shieldfunds(Decimal("4.0"), z_funding)
        shield_txid = shield_res["txid"]
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(
            self,
            node,
            owner,
            mine_addr,
            z_funding,
            min_notes=16,
            topup_amount=Decimal("0.25"),
            sync_fun=self.no_op,
        )

        owner_balance = Decimal(owner.z_getbalance()["balance"])
        assert owner_balance > Decimal("0")

        ordering_addr_a = owner.z_getnewaddress()
        ordering_addr_b = owner.z_getnewaddress()
        ordering_export_a = owner.z_exportviewingkey(ordering_addr_a)
        ordering_export_b = owner.z_exportviewingkey(ordering_addr_b)

        self.log.info("Address returned by import must match the imported key material, independent of key ordering")
        ordered_exports = sorted(
            [ordering_export_a, ordering_export_b],
            key=lambda item: item["address"],
            reverse=True,
        )
        first_import = viewer.z_importviewingkey(
            ordered_exports[0]["viewing_key"],
            ordered_exports[0]["kem_public_key"],
            ordered_exports[0]["address"],
            False,
            0,
        )
        assert_equal(first_import["success"], True)
        assert_equal(first_import["address"], ordered_exports[0]["address"])
        second_import = viewer.z_importviewingkey(
            ordered_exports[1]["viewing_key"],
            ordered_exports[1]["kem_public_key"],
            ordered_exports[1]["address"],
            False,
            0,
        )
        assert_equal(second_import["success"], True)
        assert_equal(second_import["address"], ordered_exports[1]["address"])

        self.log.info("Import with mismatched ML-KEM key material must fail")
        bad_kem_pk = list(ordering_export_a["kem_public_key"])
        bad_kem_pk[-1] = "0" if bad_kem_pk[-1] != "0" else "1"
        bad_kem_pk = "".join(bad_kem_pk)
        assert_raises_rpc_error(
            -8,
            "Invalid viewing key material",
            viewer.z_importviewingkey,
            ordering_export_a["viewing_key"],
            bad_kem_pk,
            ordering_export_a["address"],
            False,
            0,
        )

        self.log.info("Import with malformed key lengths must fail with parameter errors")
        assert_raises_rpc_error(
            -8,
            "Invalid viewing_key",
            viewer.z_importviewingkey,
            ordering_export_a["viewing_key"][:-2],
            ordering_export_a["kem_public_key"],
            ordering_export_a["address"],
            False,
            0,
        )

        self.log.info("disable_private_keys wallets must reject shielded viewing-key imports with a clear error")
        assert_raises_rpc_error(
            -4,
            "Shielded viewing keys require an encrypted blank wallet with private keys enabled",
            viewer_nokeys.z_importviewingkey,
            ordering_export_a["viewing_key"],
            ordering_export_a["kem_public_key"],
            ordering_export_a["address"],
            False,
            0,
        )
        assert_raises_rpc_error(
            -8,
            "Invalid kem_public_key",
            viewer.z_importviewingkey,
            ordering_export_a["viewing_key"],
            ordering_export_a["kem_public_key"][:-2],
            ordering_export_a["address"],
            False,
            0,
        )

        historical_addr = owner.z_getnewaddress()
        live_addr = owner.z_getnewaddress()
        historical_export = owner.z_exportviewingkey(historical_addr)
        live_export = owner.z_exportviewingkey(live_addr)
        historical_amount = Decimal("0.25")
        live_amount = Decimal("0.35")

        self.log.info("Create a historical v2_send before the viewer imports its key")
        historical_send = owner.z_sendtoaddress(
            historical_addr,
            historical_amount,
            "",
            "",
            False,
            None,
            True,
        )
        assert historical_send["txid"] in node.getrawmempool()
        assert_equal(historical_send["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Import without rescan must not backfill historical v2_send notes")
        import_result = viewer.z_importviewingkey(
            historical_export["viewing_key"],
            historical_export["kem_public_key"],
            historical_export["address"],
            False,
            0,
        )
        assert_equal(import_result["success"], True)
        assert_equal(import_result["address"], historical_addr)
        assert_equal(Decimal(viewer.z_getbalance()["balance"]), Decimal("0"))

        self.log.info("Re-import with rescan must recover historical v2_send notes")
        import_result = viewer.z_importviewingkey(
            historical_export["viewing_key"],
            historical_export["kem_public_key"],
            historical_export["address"],
            True,
            0,
        )
        assert_equal(import_result["success"], True)
        assert_equal(import_result["address"], historical_addr)
        recovered_balance = viewer.z_getbalance()
        assert_equal(Decimal(recovered_balance["balance"]), Decimal("0"))
        assert_equal(int(recovered_balance["note_count"]), 0)
        assert_equal(Decimal(recovered_balance["watchonly_balance"]), historical_amount)
        assert_equal(int(recovered_balance["watchonly_note_count"]), 1)
        assert_equal(Decimal(recovered_balance["total_balance"]), historical_amount)
        viewer_total = viewer.z_gettotalbalance()
        assert_equal(Decimal(viewer_total["shielded"]), Decimal("0"))
        assert_equal(Decimal(viewer_total["shielded_watchonly"]), historical_amount)
        assert_equal(Decimal(viewer_total["watchonly_total"]), historical_amount)
        assert_equal(Decimal(viewer_total["total_including_watchonly"]), historical_amount)

        addr_info = viewer.z_validateaddress(historical_addr)
        assert_equal(addr_info["ismine"], False)
        assert_equal(addr_info["iswatchonly"], True)

        self.log.info("Re-importing the recovered historical viewing key into owner must not downgrade spend authority")
        owner_import = owner.z_importviewingkey(
            historical_export["viewing_key"],
            historical_export["kem_public_key"],
            historical_export["address"],
            False,
            0,
        )
        assert_equal(owner_import["success"], True)
        owner_addr_info = owner.z_validateaddress(historical_addr)
        assert_equal(owner_addr_info["ismine"], True)
        assert_equal(owner_addr_info["iswatchonly"], False)

        unspent_notes = viewer.z_listunspent(1, 9999999, True)
        assert len(unspent_notes) >= 1
        assert any(note["amount"] == historical_amount and note["spendable"] == False for note in unspent_notes)

        self.log.info("Viewer can recover historical v2_send data from imported key material but cannot spend")
        tx_view = viewer.z_viewtransaction(historical_send["txid"])
        assert_equal(tx_view["txid"], historical_send["txid"])
        assert_equal(tx_view["family"], "v2_send")
        assert len(tx_view["outputs"]) >= 1
        assert_equal(tx_view["output_chunks"], [])
        assert any(output["amount"] == historical_amount and output["is_ours"] for output in tx_view["outputs"])

        self.log.info("Import another viewing key without rescan, then verify live v2_send discovery via scan hints")
        pre_live_balance = Decimal(viewer.z_getbalance(0)["watchonly_balance"])
        live_import = viewer.z_importviewingkey(
            live_export["viewing_key"],
            live_export["kem_public_key"],
            live_export["address"],
            False,
            0,
        )
        assert_equal(live_import["success"], True)
        assert_equal(live_import["address"], live_addr)

        live_send = owner.z_sendtoaddress(
            live_addr,
            live_amount,
            "",
            "",
            False,
            None,
            True,
        )
        assert live_send["txid"] in node.getrawmempool()
        assert_equal(live_send["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        live_view = viewer.z_viewtransaction(live_send["txid"])
        assert_equal(live_view["family"], "v2_send")
        assert_equal(live_view["output_chunks"], [])
        assert any(output["amount"] == live_amount and output["is_ours"] for output in live_view["outputs"])
        live_unspent = viewer.z_listunspent(0, 9999999, True)
        assert any(note["amount"] == live_amount and note["spendable"] == False for note in live_unspent)
        live_balance = viewer.z_getbalance(0)
        assert_equal(Decimal(live_balance["balance"]), Decimal("0"))
        assert Decimal(live_balance["watchonly_balance"]) >= pre_live_balance + live_amount
        assert Decimal(live_balance["total_balance"]) >= pre_live_balance + live_amount

        self.log.info("Advance one more block so the newly discovered view-only note is confirmed past the tip boundary")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        confirmed_live_balance = viewer.z_getbalance()
        assert_equal(Decimal(confirmed_live_balance["balance"]), Decimal("0"))
        assert Decimal(confirmed_live_balance["watchonly_balance"]) >= pre_live_balance + live_amount
        assert Decimal(confirmed_live_balance["total_balance"]) >= pre_live_balance + live_amount
        live_unspent = viewer.z_listunspent(1, 9999999, True)
        assert any(note["amount"] == live_amount and note["spendable"] == False for note in live_unspent)

        assert_raises_rpc_error(
            -4,
            "no spendable notes selected",
            viewer.z_sendmany,
            [{"address": owner.getnewaddress(), "amount": Decimal("0.1")}],
        )


if __name__ == "__main__":
    WalletShieldedViewingKeyRescanTest(__file__).main()
