#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import json
from decimal import Decimal
from pathlib import Path

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
    unlock_wallet,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


DISABLE_HEIGHT = 132


class WalletShieldedPostForkPrivacyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            f"-regtestshieldedmatrictdisableheight={DISABLE_HEIGHT}",
        ]]
        self.rpc_timeout = 900

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        node.createwallet(wallet_name="depositonly", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        deposit_wallet = encrypt_and_unlock_wallet(node, "depositonly")

        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self,
            node,
            wallet,
            mine_addr,
            Decimal("8.0"),
            maturity_blocks=DISABLE_HEIGHT - 3,
            sync_fun=self.no_op,
        )
        assert_equal(node.getblockcount(), DISABLE_HEIGHT - 2)

        self.log.info("Seed shielded balance before the fork boundary, then cross into the post-fork regime")
        z_from = wallet.z_getnewaddress()
        viewing_key_addr = wallet.z_getnewaddress()
        pre_fork_viewing_key = wallet.z_exportviewingkey(viewing_key_addr)
        shielded_tx = wallet.z_shieldfunds(Decimal("2.0"), z_from)
        assert shielded_tx["txid"] in node.getrawmempool()
        self.log.info("Populate the anonymity pool before the wallet switches to post-fork build rules")
        ensure_ring_diversity(
            self,
            node,
            wallet,
            mine_addr,
            z_from,
            min_notes=16,
            topup_amount=Decimal("0.25"),
        )
        assert_equal(node.getblockcount(), DISABLE_HEIGHT - 1)
        assert shielded_tx["txid"] not in node.getrawmempool()

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), DISABLE_HEIGHT)

        self.log.info("Post-fork non-coinbase transparent shielding stays disabled in favor of explicit ingress")
        deposit_taddr = deposit_wallet.getnewaddress()
        wallet.sendtoaddress(deposit_taddr, Decimal("1.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_raises_rpc_error(
            -4,
            "post-fork direct transparent shielding is limited to mature coinbase outputs; use bridge ingress for general transparent deposits",
            deposit_wallet.z_shieldfunds,
            Decimal("0.25"),
            deposit_wallet.z_getnewaddress(),
        )

        self.log.info("Post-fork shielded address lifecycle metadata is exposed and managed through RPC")
        balance_before_lifecycle = wallet.z_getbalance()
        unspent_before_lifecycle = wallet.z_listunspent(0, 9999999, False)
        unspent_total_before_lifecycle = sum(
            Decimal(str(note["total_amount"])) for note in unspent_before_lifecycle
        )
        preferred_before = next(entry["address"] for entry in wallet.z_listaddresses() if entry["preferred_receive"])
        rotated_source = preferred_before
        rotation = wallet.z_rotateaddress(rotated_source)
        assert_equal(rotation["address"], rotated_source)
        assert_equal(rotation["lifecycle_state"], "rotated")
        successor = rotation["successor"]
        assert rotation["txid"] in node.getrawmempool()

        rotated_info = wallet.z_validateaddress(rotated_source)
        assert_equal(rotated_info["lifecycle_state"], "rotated")
        assert rotated_info["has_successor"]
        assert_equal(rotated_info["successor"], successor)
        assert not rotated_info["has_predecessor"]

        successor_info = wallet.z_validateaddress(successor)
        assert_equal(successor_info["lifecycle_state"], "active")
        assert successor_info["has_predecessor"]
        assert_equal(successor_info["predecessor"], rotated_source)

        revoked_addr = wallet.z_getnewaddress()
        revoke = wallet.z_revokeaddress(revoked_addr)
        assert_equal(revoke["address"], revoked_addr)
        assert_equal(revoke["lifecycle_state"], "revoked")
        assert revoke["txid"] in node.getrawmempool()
        revoked_info = wallet.z_validateaddress(revoked_addr)
        assert_equal(revoked_info["lifecycle_state"], "revoked")
        assert not revoked_info["has_successor"]

        listed = {entry["address"]: entry for entry in wallet.z_listaddresses()}
        assert_equal(listed[rotated_source]["lifecycle_state"], "rotated")
        assert not listed[rotated_source]["preferred_receive"]
        assert_equal(listed[successor]["lifecycle_state"], "active")
        assert listed[successor]["preferred_receive"]
        assert_equal(listed[revoked_addr]["lifecycle_state"], "revoked")
        assert not listed[revoked_addr]["preferred_receive"]

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert rotation["txid"] not in node.getrawmempool()
        assert revoke["txid"] not in node.getrawmempool()
        balance_after_lifecycle = wallet.z_getbalance()
        unspent_after_lifecycle = wallet.z_listunspent(0, 9999999, False)
        assert_equal(balance_after_lifecycle["balance"], balance_before_lifecycle["balance"])
        assert_equal(balance_after_lifecycle["note_count"], balance_before_lifecycle["note_count"])
        assert_equal(len(unspent_after_lifecycle), len(unspent_before_lifecycle))
        assert_equal(
            sum(Decimal(str(note["total_amount"])) for note in unspent_after_lifecycle),
            unspent_total_before_lifecycle,
        )

        self.log.info("Lifecycle metadata and spendability survive restart")
        self.restart_node(0)
        node = self.nodes[0]
        node.loadwallet("shielded")
        node.loadwallet("depositonly")
        wallet = unlock_wallet(node, "shielded")
        deposit_wallet = unlock_wallet(node, "depositonly")

        rotated_info = wallet.z_validateaddress(rotated_source)
        assert_equal(rotated_info["lifecycle_state"], "rotated")
        assert_equal(rotated_info["successor"], successor)
        successor_info = wallet.z_validateaddress(successor)
        assert_equal(successor_info["lifecycle_state"], "active")
        revoked_info = wallet.z_validateaddress(revoked_addr)
        assert_equal(revoked_info["lifecycle_state"], "revoked")

        listed = {entry["address"]: entry for entry in wallet.z_listaddresses()}
        assert_equal(listed[rotated_source]["lifecycle_state"], "rotated")
        assert not listed[rotated_source]["preferred_receive"]
        assert_equal(listed[successor]["lifecycle_state"], "active")
        assert listed[successor]["preferred_receive"]
        assert_equal(listed[revoked_addr]["lifecycle_state"], "revoked")
        assert not listed[revoked_addr]["preferred_receive"]
        unspent_after_restart = wallet.z_listunspent(0, 9999999, False)
        assert_equal(len(unspent_after_restart), len(unspent_before_lifecycle))
        assert_equal(
            sum(Decimal(str(note["total_amount"])) for note in unspent_after_restart),
            unspent_total_before_lifecycle,
        )

        self.log.info("Default post-fork shielded RPCs redact sensitive note identifiers")
        txid = wallet.z_sendmany([{"address": wallet.z_getnewaddress(), "amount": Decimal("0.10")}])["txid"]
        view = wallet.z_viewtransaction(txid)
        assert_equal(view["family"], "shielded_v2")
        assert view["family_redacted"]
        assert "value_balance" not in view
        assert view["value_balance_redacted"]
        assert_greater_than(len(view["spends"]), 0)
        assert all("nullifier" not in spend for spend in view["spends"])
        assert all(spend["nullifier_redacted"] for spend in view["spends"])
        assert all("commitment" not in output for output in view["outputs"])
        assert all(output["commitment_redacted"] for output in view["outputs"])
        assert view["output_chunks_redacted"]

        notes = wallet.z_listunspent(0, 9999999, False)
        assert_greater_than(len(notes), 0)
        assert all(note["summary_redacted"] for note in notes)
        assert all("nullifier" not in note for note in notes)
        assert all(note["nullifier_redacted"] for note in notes)
        assert all("tree_position" not in note for note in notes)
        assert all(note["tree_position_redacted"] for note in notes)
        assert all("commitment" not in note for note in notes)
        assert all(note["commitment_redacted"] for note in notes)
        assert all("block_hash" not in note for note in notes)
        assert all(note["block_hash_redacted"] for note in notes)
        assert sum(Decimal(str(note["total_amount"])) for note in notes) > Decimal("0")

        self.log.info("Explicit opt-in restores the legacy operator disclosure surface")
        sensitive_view = wallet.z_viewtransaction(txid, True)
        assert "value_balance" in sensitive_view
        assert_equal(sensitive_view["family"], "v2_send")
        assert any("nullifier" in spend for spend in sensitive_view["spends"])
        assert any("commitment" in output for output in sensitive_view["outputs"])

        sensitive_notes = wallet.z_listunspent(0, 9999999, False, True)
        assert any("nullifier" in note for note in sensitive_notes)
        assert any("tree_position" in note for note in sensitive_notes)
        assert any("commitment" in note for note in sensitive_notes)
        assert any("block_hash" in note for note in sensitive_notes)

        self.log.info("Post-fork mixed direct unshield is disabled in favor of explicit bridge/egress settlement")
        t_dest = wallet.getnewaddress()
        assert_raises_rpc_error(
            -4,
            "post-fork mixed shielded-to-transparent direct sends are disabled; use bridge unshield",
            wallet.z_sendmany,
            [{"address": t_dest, "amount": Decimal("0.05")}],
        )

        self.log.info("Raw viewing-key sharing is disabled after the post-fork privacy boundary")
        export_addr = wallet.z_getnewaddress()
        assert_raises_rpc_error(
            -4,
            "z_exportviewingkey is disabled after block",
            wallet.z_exportviewingkey,
            export_addr,
        )
        assert_raises_rpc_error(
            -4,
            "z_exportviewingkey is disabled after block",
            wallet.z_exportviewingkey,
            export_addr,
            True,
        )
        assert_raises_rpc_error(
            -4,
            "z_importviewingkey is disabled after block",
            deposit_wallet.z_importviewingkey,
            pre_fork_viewing_key["viewing_key"],
            pre_fork_viewing_key["kem_public_key"],
            pre_fork_viewing_key["address"],
            False,
            0,
        )

        self.log.info("Post-fork wallet bundles default to metadata-only exports without raw viewing keys")
        bundle_dir = node.datadir_path / "postfork-bundle"
        bundle = wallet.backupwalletbundle(bundle_dir)
        bundle_path = Path(bundle["bundle_dir"])
        manifest = json.loads((bundle_path / "manifest.json").read_text(encoding="utf-8"))
        assert_equal(manifest["include_viewing_keys"], False)
        assert_equal((bundle_path / "shielded_viewing_keys" / "index.tsv").read_text(encoding="utf-8"), "")
        assert (bundle_path / "getbalances.json").is_file()

        archive_path = node.datadir_path / "postfork-bundle.btx"
        archive = wallet.backupwalletbundlearchive(archive_path, "archive-pass")
        assert_equal(archive["integrity"]["integrity_ok"], True)
        assert "getbalances.json" in archive["bundle_files"]

        assert_raises_rpc_error(
            -4,
            "backupwalletbundle viewing-key export is disabled after block",
            wallet.backupwalletbundle,
            node.datadir_path / "postfork-bundle-viewing-keys",
            None,
            True,
        )

        self.log.info("Post-fork shielded dust policy rejects tiny direct sends")
        assert_raises_rpc_error(
            -4,
            "shielded recipient amount below dust threshold",
            wallet.z_sendmany,
            [{"address": wallet.z_getnewaddress(), "amount": Decimal("0.00000001")}],
        )

        self.log.info("Post-fork transparent-to-shielded fallback APIs are disabled in favor of explicit ingress")
        assert_raises_rpc_error(
            -4,
            "post-fork direct transparent shielding is disabled; use bridge ingress",
            deposit_wallet.z_sendmany,
            [{"address": wallet.z_getnewaddress(), "amount": Decimal("0.00000001")}],
        )


if __name__ == "__main__":
    WalletShieldedPostForkPrivacyTest(__file__).main()
