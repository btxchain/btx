#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Bridge-in view-grant coverage."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    create_bridge_wallet,
    find_output,
    get_kem_public_key,
    mine_block,
    planbatchin,
    planin,
    sign_batch_authorization,
)
from test_framework.shielded_utils import SHIELDED_WALLET_PASSPHRASE, encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeViewGrantTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-regtestshieldedmatrictdisableheight=1"],
            ["-regtestshieldedmatrictdisableheight=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        operator_node = self.nodes[1]
        self.connect_nodes(0, 1)

        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_viewgrant")
        node.createwallet(wallet_name="bridge_viewgrant_recipient", descriptors=True)
        recipient_wallet = encrypt_and_unlock_wallet(node, "bridge_viewgrant_recipient")
        self.sync_blocks()
        operator_node.createwallet(wallet_name="operator", descriptors=True)
        operator_wallet = encrypt_and_unlock_wallet(operator_node, "operator")

        recipient = recipient_wallet.z_getnewaddress()
        recipient_info = recipient_wallet.z_validateaddress(recipient)
        operator_zaddr, operator_kem_pubkey = get_kem_public_key(operator_wallet)
        refund_lock_height = node.getblockcount() + 20

        self.log.info("Bridge-in planning should embed operator view grants only when requested")
        with_grant, operator_key, refund_key = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(30),
            operation_id=bridge_hex(31),
            recipient=recipient,
            operator_view_pubkeys=[operator_kem_pubkey],
        )
        structured_grant, _, _ = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(34),
            operation_id=bridge_hex(35),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            memo="audit memo",
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "structured_disclosure",
                "disclosure_fields": ["amount", "recipient", "memo", "sender"],
            }],
        )
        assert_raises_rpc_error(
            -8,
            "legacy_audit requires allow_legacy_audit_view_grants=true",
            planin,
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(0x2A),
            operation_id=bridge_hex(0x2B),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "legacy_audit",
            }],
        )
        assert_raises_rpc_error(
            -8,
            "disclosure_policy.required_grants[0].format legacy_audit requires allow_legacy_audit_view_grants=true",
            planin,
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(0x42),
            operation_id=bridge_hex(0x43),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            disclosure_policy={
                "threshold_amount": Decimal("0.1"),
                "required_grants": [{
                    "pubkey": operator_kem_pubkey,
                    "format": "legacy_audit",
                }],
            },
        )
        default_format_grant, _, _ = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(0x2C),
            operation_id=bridge_hex(0x2D),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
            }],
        )
        policy_default_grant, _, _ = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(0x44),
            operation_id=bridge_hex(0x45),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            disclosure_policy={
                "threshold_amount": Decimal("0.1"),
                "required_grants": [{
                    "pubkey": operator_kem_pubkey,
                }],
            },
        )
        legacy_grant, _, _ = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(36),
            operation_id=bridge_hex(37),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "legacy_audit",
            }],
            allow_legacy_audit_view_grants=True,
        )
        without_grant, _, _ = planin(
            wallet,
            Decimal("2.5"),
            refund_lock_height,
            bridge_id=bridge_hex(32),
            operation_id=bridge_hex(33),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
        )

        assert_equal(with_grant["bundle"]["shielded_output_count"], 1)
        assert_equal(with_grant["bundle"]["view_grant_count"], 1)
        assert_equal(len(with_grant["bundle"]["view_grants"]), 1)
        assert_equal(with_grant["bundle"]["view_grants"][0]["format"], "structured_disclosure")
        assert_equal(
            with_grant["bundle"]["view_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )
        assert len(with_grant["bundle"]["view_grants"][0]["kem_ciphertext"]) > 0
        assert len(with_grant["bundle"]["view_grants"][0]["nonce"]) > 0
        assert len(with_grant["bundle"]["view_grants"][0]["encrypted_data"]) > 0
        assert len(with_grant["bundle"]["view_grants"][0]["view_grant_hex"]) > 0
        assert_equal(with_grant["operator_view_grants"][0]["format"], "structured_disclosure")

        assert_equal(without_grant["bundle"]["view_grant_count"], 0)
        assert_equal(without_grant["bundle"]["view_grants"], [])

        assert_equal(structured_grant["bundle"]["view_grant_count"], 1)
        assert_equal(structured_grant["bundle"]["view_grants"][0]["format"], "structured_disclosure")
        assert_equal(
            structured_grant["bundle"]["view_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "memo", "sender"],
        )
        assert_equal(
            structured_grant["operator_view_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "memo", "sender"],
        )
        assert_equal(legacy_grant["bundle"]["view_grant_count"], 1)
        assert_equal(legacy_grant["bundle"]["view_grants"][0]["format"], "legacy_audit")
        assert_equal(default_format_grant["bundle"]["view_grants"][0]["format"], "structured_disclosure")
        assert_equal(
            default_format_grant["bundle"]["view_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )
        assert_equal(policy_default_grant["bundle"]["view_grant_count"], 1)
        assert_equal(
            policy_default_grant["disclosure_policy"]["required_grants"][0]["format"],
            "structured_disclosure",
        )
        assert_equal(
            policy_default_grant["disclosure_policy"]["required_grants"][0]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )

        self.log.info("A reloaded encrypted operator wallet should decrypt after explicit unlock")
        operator_wallet.walletlock()
        operator_node.unloadwallet("operator")
        operator_node.loadwallet("operator")
        operator_wallet = operator_node.get_wallet_rpc("operator")
        assert_raises_rpc_error(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            operator_wallet.bridge_decryptviewgrant,
            structured_grant["bundle"]["view_grants"][0],
        )
        operator_wallet.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 120)

        self.log.info("A separate operator wallet should decrypt only grants addressed to its local KEM key")
        pubkey_default_decrypted = operator_wallet.bridge_decryptviewgrant(with_grant["bundle"]["view_grants"][0])
        assert_equal(pubkey_default_decrypted["format"], "structured_disclosure")
        assert_equal(pubkey_default_decrypted["metadata_authenticated"], True)
        assert_equal(pubkey_default_decrypted["metadata_verified"], True)
        assert_equal(
            pubkey_default_decrypted["payload"]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )
        assert_equal(pubkey_default_decrypted["payload"]["amount"], Decimal("2.5"))
        assert_equal(pubkey_default_decrypted["payload"]["recipient_pk_hash"], recipient_info["pk_hash"])
        assert_equal(pubkey_default_decrypted["payload"]["sender"]["bridge_id"], bridge_hex(30))
        assert_equal(pubkey_default_decrypted["payload"]["sender"]["operation_id"], bridge_hex(31))
        assert "memo" not in pubkey_default_decrypted["payload"]
        assert "memo_hex" not in pubkey_default_decrypted["payload"]

        default_format_decrypted = operator_wallet.bridge_decryptviewgrant(
            default_format_grant["bundle"]["view_grants"][0]
        )
        assert_equal(default_format_decrypted["format"], "structured_disclosure")
        assert_equal(default_format_decrypted["metadata_authenticated"], True)
        assert_equal(default_format_decrypted["metadata_verified"], True)
        assert_equal(
            default_format_decrypted["payload"]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )
        assert_equal(default_format_decrypted["payload"]["amount"], Decimal("2.5"))
        assert_equal(default_format_decrypted["payload"]["recipient_pk_hash"], recipient_info["pk_hash"])
        assert_equal(default_format_decrypted["payload"]["sender"]["bridge_id"], bridge_hex(0x2C))
        assert_equal(default_format_decrypted["payload"]["sender"]["operation_id"], bridge_hex(0x2D))
        assert "memo" not in default_format_decrypted["payload"]
        assert "memo_hex" not in default_format_decrypted["payload"]

        policy_default_decrypted = operator_wallet.bridge_decryptviewgrant(
            policy_default_grant["bundle"]["view_grants"][0]
        )
        assert_equal(policy_default_decrypted["format"], "structured_disclosure")
        assert_equal(policy_default_decrypted["metadata_authenticated"], True)
        assert_equal(policy_default_decrypted["metadata_verified"], True)
        assert_equal(
            policy_default_decrypted["payload"]["disclosure_fields"],
            ["amount", "recipient", "sender"],
        )
        assert_equal(policy_default_decrypted["payload"]["amount"], Decimal("2.5"))
        assert_equal(policy_default_decrypted["payload"]["recipient_pk_hash"], recipient_info["pk_hash"])
        assert_equal(policy_default_decrypted["payload"]["sender"]["bridge_id"], bridge_hex(0x44))
        assert_equal(policy_default_decrypted["payload"]["sender"]["operation_id"], bridge_hex(0x45))
        assert "memo" not in policy_default_decrypted["payload"]
        assert "memo_hex" not in policy_default_decrypted["payload"]

        decrypted = operator_wallet.bridge_decryptviewgrant(structured_grant["bundle"]["view_grants"][0])
        assert_equal(decrypted["decrypted"], True)
        assert_equal(decrypted["address"], operator_zaddr)
        assert_equal(decrypted["format"], "structured_disclosure")
        assert_equal(decrypted["metadata_authenticated"], True)
        assert_equal(decrypted["metadata_verified"], True)
        assert_equal(decrypted["payload"]["amount"], Decimal("2.5"))
        assert_equal(decrypted["payload"]["recipient_pk_hash"], recipient_info["pk_hash"])
        assert_equal(decrypted["payload"]["memo"], "audit memo")
        assert_equal(decrypted["payload"]["sender"]["bridge_id"], bridge_hex(34))
        assert_equal(decrypted["payload"]["sender"]["operation_id"], bridge_hex(35))
        expected_verified = operator_wallet.bridge_decryptviewgrant(
            structured_grant["bundle"]["view_grants"][0],
            "structured_disclosure",
            {
                "amount": Decimal("2.5"),
                "recipient_pk_hash": recipient_info["pk_hash"],
                "memo": "audit memo",
                "sender": {"bridge_id": bridge_hex(34), "operation_id": bridge_hex(35)},
            },
        )
        assert_equal(expected_verified["expected_verified"], True)
        assert_raises_rpc_error(
            -8,
            "amount does not match expected amount",
            operator_wallet.bridge_decryptviewgrant,
            structured_grant["bundle"]["view_grants"][0],
            "structured_disclosure",
            {"amount": Decimal("2.6")},
        )

        amount_only_grant, _, _ = planin(
            wallet,
            Decimal("1.5"),
            refund_lock_height,
            bridge_id=bridge_hex(40),
            operation_id=bridge_hex(41),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            memo="hidden memo",
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "structured_disclosure",
                "disclosure_fields": ["amount"],
            }],
        )
        amount_only_decrypted = operator_wallet.bridge_decryptviewgrant(
            amount_only_grant["bundle"]["view_grants"][0],
            "structured_disclosure",
        )
        assert_equal(amount_only_decrypted["payload"]["disclosure_fields"], ["amount"])
        assert_equal(amount_only_decrypted["metadata_authenticated"], True)
        assert_equal(amount_only_decrypted["payload"]["amount"], Decimal("1.5"))
        assert "recipient_pk_hash" not in amount_only_decrypted["payload"]
        assert "memo" not in amount_only_decrypted["payload"]
        assert "memo_hex" not in amount_only_decrypted["payload"]
        assert "sender" not in amount_only_decrypted["payload"]

        assert_raises_rpc_error(
            -4,
            "metadata-bound grants require view_grant metadata",
            operator_wallet.bridge_decryptviewgrant,
            structured_grant["bundle"]["view_grants"][0]["view_grant_hex"],
        )
        assert_raises_rpc_error(
            -4,
            "metadata-bound grants require view_grant metadata",
            operator_node.cli("-rpcwallet=operator").bridge_decryptviewgrant,
            structured_grant["bundle"]["view_grants"][0]["view_grant_hex"],
        )
        assert_raises_rpc_error(
            -8,
            "format must be legacy_audit or structured_disclosure",
            operator_wallet.bridge_decryptviewgrant,
            structured_grant["bundle"]["view_grants"][0],
            "not_a_format",
        )
        mislabeled_structured = dict(structured_grant["bundle"]["view_grants"][0])
        mislabeled_structured["format"] = "legacy_audit"
        assert_raises_rpc_error(
            -8,
            "view_grant.disclosure_fields is only valid for structured_disclosure",
            operator_wallet.bridge_decryptviewgrant,
            mislabeled_structured,
        )
        wrong_fields = dict(structured_grant["bundle"]["view_grants"][0])
        wrong_fields["disclosure_fields"] = ["amount"]
        assert_raises_rpc_error(
            -4,
            "with the supplied metadata",
            operator_wallet.bridge_decryptviewgrant,
            wrong_fields,
        )
        assert_raises_rpc_error(
            -8,
            "view_grant.view_grant_hex is not a valid bridge view grant",
            operator_wallet.bridge_decryptviewgrant,
            {"view_grant_hex": structured_grant["bundle"]["view_grants"][0]["view_grant_hex"] + "00"},
        )

        legacy_decrypted = operator_wallet.bridge_decryptviewgrant(
            legacy_grant["bundle"]["view_grants"][0],
            "legacy_audit",
        )
        assert_equal(legacy_decrypted["format"], "legacy_audit")
        assert_equal(legacy_decrypted["payload"]["amount"], Decimal("2.5"))
        assert_equal(legacy_decrypted["payload"]["recipient_pk_hash"], recipient_info["pk_hash"])
        assert len(legacy_decrypted["payload"]["note_commitment"]) == 64
        legacy_auto_decrypted = operator_wallet.bridge_decryptviewgrant(legacy_grant["bundle"]["view_grants"][0])
        assert_equal(legacy_auto_decrypted["format"], "legacy_audit")
        assert_equal(legacy_auto_decrypted["payload"]["amount"], Decimal("2.5"))
        assert_raises_rpc_error(
            -8,
            "Decrypted view grant payload is not structured_disclosure",
            operator_wallet.bridge_decryptviewgrant,
            legacy_grant["bundle"]["view_grants"][0],
            "structured_disclosure",
        )

        assert_raises_rpc_error(
            -4,
            "No local shielded viewing key could decrypt view grant",
            wallet.bridge_decryptviewgrant,
            structured_grant["bundle"]["view_grants"][0],
        )

        tampered = dict(structured_grant["bundle"]["view_grants"][0])
        tampered.pop("view_grant_hex", None)
        tampered["encrypted_data"] = (
            ("0" if tampered["encrypted_data"][0] != "0" else "1") +
            tampered["encrypted_data"][1:]
        )
        assert_raises_rpc_error(
            -4,
            "No local shielded viewing key could decrypt view grant",
            operator_wallet.bridge_decryptviewgrant,
            tampered,
        )
        tampered_mixed = dict(structured_grant["bundle"]["view_grants"][0])
        tampered_mixed["encrypted_data"] = (
            ("0" if tampered_mixed["encrypted_data"][0] != "0" else "1") +
            tampered_mixed["encrypted_data"][1:]
        )
        assert_raises_rpc_error(
            -8,
            "view_grant.encrypted_data does not match view_grant.view_grant_hex",
            operator_wallet.bridge_decryptviewgrant,
            tampered_mixed,
        )

        self.log.info("Batch bridge-in planning should expose decryptable structured grants")
        batch_amounts = [Decimal("1.00"), Decimal("1.25")]
        batch_bridge_id = bridge_hex(38)
        batch_operation_id = bridge_hex(39)
        batch_entries = []
        for index, amount in enumerate(batch_amounts):
            signed = sign_batch_authorization(
                wallet,
                wallet.getnewaddress(address_type="p2mr"),
                "bridge_in",
                {
                    "kind": "shield_credit",
                    "wallet_id": bridge_hex(0x2400 + index),
                    "destination_id": bridge_hex(0x2500 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x2600 + index),
                },
                bridge_id=batch_bridge_id,
                operation_id=batch_operation_id,
            )
            batch_entries.append({"authorization_hex": signed["authorization_hex"]})
        assert_raises_rpc_error(
            -8,
            "operator_view_grants[0].format legacy_audit requires allow_legacy_audit_view_grants=true",
            planbatchin,
            wallet,
            batch_entries,
            refund_lock_height,
            bridge_id=batch_bridge_id,
            operation_id=batch_operation_id,
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "legacy_audit",
            }],
        )
        batch_legacy_plan, _, _ = planbatchin(
            wallet,
            batch_entries,
            refund_lock_height,
            bridge_id=batch_bridge_id,
            operation_id=batch_operation_id,
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "legacy_audit",
            }],
            allow_legacy_audit_view_grants=True,
        )
        assert_equal(batch_legacy_plan["bundle"]["view_grant_count"], 1)
        assert_equal(batch_legacy_plan["bundle"]["view_grants"][0]["format"], "legacy_audit")
        batch_legacy_decrypted = operator_wallet.bridge_decryptviewgrant(
            batch_legacy_plan["bundle"]["view_grants"][0],
            "legacy_audit",
        )
        assert_equal(batch_legacy_decrypted["payload"]["amount"], sum(batch_amounts, Decimal("0")))
        assert_equal(batch_legacy_decrypted["payload"]["recipient_pk_hash"], recipient_info["pk_hash"])
        assert len(batch_legacy_decrypted["payload"]["note_commitment"]) == 64
        batch_plan, _, _ = planbatchin(
            wallet,
            batch_entries,
            refund_lock_height,
            bridge_id=batch_bridge_id,
            operation_id=batch_operation_id,
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": operator_kem_pubkey,
                "format": "structured_disclosure",
                "disclosure_fields": ["amount", "memo", "sender"],
            }],
        )
        assert_equal(batch_plan["bundle"]["view_grant_count"], 1)
        batch_decrypted = operator_wallet.bridge_decryptviewgrant(batch_plan["bundle"]["view_grants"][0])
        assert_equal(batch_decrypted["format"], "structured_disclosure")
        assert_equal(batch_decrypted["payload"]["amount"], sum(batch_amounts, Decimal("0")))
        assert_equal(batch_decrypted["payload"]["memo_hex"], batch_plan["batch_commitment_hex"])
        assert "memo" not in batch_decrypted["payload"]
        assert_equal(batch_decrypted["payload"]["sender"]["bridge_id"], batch_bridge_id)
        assert_equal(batch_decrypted["payload"]["sender"]["operation_id"], batch_operation_id)

        self.log.info("Mine the bridge settlement and decrypt the grant retrieved from peer transaction JSON")
        mine_addr = wallet.getnewaddress(address_type="p2mr")
        fee_margin = Decimal("0.00020000")
        funding_txid = wallet.sendtoaddress(structured_grant["bridge_address"], Decimal("2.5") + fee_margin)
        mine_block(self, node, mine_addr)
        self.sync_blocks()
        vout, value = find_output(node, funding_txid, structured_grant["bridge_address"], wallet)
        assert_raises_rpc_error(
            -8,
            "accept_plan_view_grants=true",
            wallet.bridge_submitshieldtx,
            structured_grant["plan_hex"],
            funding_txid,
            vout,
            value,
            {"track_pending": False, "enforce_fee_headroom": False},
        )
        submitted = wallet.bridge_submitshieldtx(
            structured_grant["plan_hex"],
            funding_txid,
            vout,
            value,
            {"track_pending": False, "enforce_fee_headroom": False, "accept_plan_view_grants": True},
        )
        assert_equal(submitted["selected_path"], "normal")
        assert_equal(submitted["bridge_root"], structured_grant["bridge_root"])
        assert_equal(submitted["ctv_hash"], structured_grant["ctv_hash"])
        settlement_txid = submitted["txid"]
        mine_block(self, node, mine_addr)
        self.sync_blocks()
        node.syncwithvalidationinterfacequeue()
        self.wait_until(
            lambda: Decimal(recipient_wallet.z_getbalance()["total_balance"]) == Decimal("2.5"),
            timeout=60,
        )
        recipient_balance = recipient_wallet.z_getbalance()
        assert_equal(Decimal(recipient_balance["balance"]), Decimal("0"))
        assert_equal(Decimal(recipient_balance["recovery_only_balance"]), Decimal("2.5"))
        assert_equal(Decimal(recipient_balance["total_balance"]), Decimal("2.5"))

        block = operator_node.getblock(operator_node.getbestblockhash(), 2)
        settlement = next(tx for tx in block["tx"] if tx["txid"] == settlement_txid)
        chain_grants = settlement["shielded"]["view_grants"]
        assert_equal(len(chain_grants), 1)
        assert_equal(chain_grants[0]["view_grant_hex"], structured_grant["bundle"]["view_grants"][0]["view_grant_hex"])
        chain_grant_with_metadata = dict(structured_grant["bundle"]["view_grants"][0])
        chain_grant_with_metadata.update(chain_grants[0])
        chain_decrypted = operator_wallet.bridge_decryptviewgrant(
            chain_grant_with_metadata,
            "structured_disclosure",
            {
                "amount": Decimal("2.5"),
                "recipient_pk_hash": recipient_info["pk_hash"],
                "memo": "audit memo",
                "sender": {"bridge_id": bridge_hex(34), "operation_id": bridge_hex(35)},
            },
        )
        assert_equal(chain_decrypted["metadata_authenticated"], True)
        assert_equal(chain_decrypted["expected_verified"], True)
        assert_equal(chain_decrypted["payload"]["amount"], Decimal("2.5"))
        assert_equal(chain_decrypted["payload"]["memo"], "audit memo")


if __name__ == "__main__":
    WalletBridgeViewGrantTest(__file__).main()
