#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for bridge-in planning and view grants."""

from decimal import Decimal

from test_framework.bridge_utils import bridge_hex, create_bridge_wallet, find_output, get_kem_public_key, mine_block, planin
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgePlanInTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.privacy_redesign_height = 150
        self.extra_args = [[f"-regtestshieldedmatrictdisableheight={self.privacy_redesign_height}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_planin")

        recipient = wallet.z_getnewaddress()
        recipient_info = wallet.z_validateaddress(recipient)
        _, disclosure_pubkey = get_kem_public_key(wallet)
        _, second_disclosure_pubkey = get_kem_public_key(wallet)
        refund_lock_height = node.getblockcount() + 10

        self.log.info("Build the same bridge-in plan twice and confirm deterministic output")
        first, operator_key, refund_key = planin(
            wallet,
            Decimal("5"),
            refund_lock_height,
            bridge_id=bridge_hex(1),
            operation_id=bridge_hex(2),
            recipient=recipient,
            memo="handoff-planin",
        )
        second, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height,
            bridge_id=bridge_hex(1),
            operation_id=bridge_hex(2),
            recipient=recipient,
            memo="handoff-planin",
            operator_key=operator_key,
            refund_key=refund_key,
        )

        assert_equal(first["kind"], "shield")
        assert_equal(first["recipient"], recipient)
        assert_equal(first["recipient_generated"], False)
        assert_equal(first["bridge_address"], second["bridge_address"])
        assert_equal(first["bridge_root"], second["bridge_root"])
        assert_equal(first["ctv_hash"], second["ctv_hash"])
        assert_equal(first["plan_hex"], second["plan_hex"])
        assert_equal(first["bundle"]["shielded_output_count"], 1)
        assert_equal(first["bundle"]["view_grant_count"], 0)
        assert_equal(first["refund_lock_height"], refund_lock_height)

        self.log.info("Operator view grants should use fresh encryption randomness")
        grant_first, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 1,
            bridge_id=bridge_hex(3),
            operation_id=bridge_hex(4),
            recipient=recipient,
            memo="handoff-planin-grant",
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": disclosure_pubkey,
                "format": "structured_disclosure",
                "disclosure_fields": ["amount", "recipient", "sender"],
            }],
        )
        grant_second, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 1,
            bridge_id=bridge_hex(3),
            operation_id=bridge_hex(4),
            recipient=recipient,
            memo="handoff-planin-grant",
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": disclosure_pubkey,
                "format": "structured_disclosure",
                "disclosure_fields": ["amount", "recipient", "sender"],
            }],
        )
        assert_equal(grant_first["operator_view_grants"], grant_second["operator_view_grants"])
        assert_equal(grant_first["bundle"]["view_grant_count"], 1)
        assert_equal(grant_second["bundle"]["view_grant_count"], 1)
        assert grant_first["bundle"]["view_grants"][0]["view_grant_hex"] != \
            grant_second["bundle"]["view_grants"][0]["view_grant_hex"]
        first_decrypted = wallet.bridge_decryptviewgrant(
            grant_first["bundle"]["view_grants"][0],
            "structured_disclosure",
        )
        second_decrypted = wallet.bridge_decryptviewgrant(
            grant_second["bundle"]["view_grants"][0],
            "structured_disclosure",
        )
        assert_equal(first_decrypted["payload"], second_decrypted["payload"])

        self.log.info("Equivalent operator view-grant sets should canonicalize request order")
        grant_a = {
            "pubkey": disclosure_pubkey,
            "format": "structured_disclosure",
            "disclosure_fields": ["amount"],
        }
        grant_b = {
            "pubkey": second_disclosure_pubkey,
            "format": "structured_disclosure",
            "disclosure_fields": ["sender"],
        }
        canonical_forward, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 2,
            bridge_id=bridge_hex(9),
            operation_id=bridge_hex(10),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[grant_a, grant_b],
        )
        canonical_reverse, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 2,
            bridge_id=bridge_hex(9),
            operation_id=bridge_hex(10),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[grant_b, grant_a],
        )
        expected_pubkeys = sorted([disclosure_pubkey, second_disclosure_pubkey])
        assert_equal(
            [grant["recipient_pubkey"] for grant in canonical_forward["operator_view_grants"]],
            expected_pubkeys,
        )
        assert_equal(
            [grant["recipient_pubkey"] for grant in canonical_forward["bundle"]["view_grants"]],
            expected_pubkeys,
        )
        assert_equal(canonical_forward["operator_view_grants"], canonical_reverse["operator_view_grants"])
        assert_equal(
            [grant["recipient_pubkey"] for grant in canonical_forward["bundle"]["view_grants"]],
            [grant["recipient_pubkey"] for grant in canonical_reverse["bundle"]["view_grants"]],
        )

        self.log.info("Pre-fork omitted and legacy grant formats should remain legacy audit grants")
        legacy_from_pubkeys, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 3,
            bridge_id=bridge_hex(11),
            operation_id=bridge_hex(12),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_pubkeys=[disclosure_pubkey],
        )
        omitted_format_legacy, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 4,
            bridge_id=bridge_hex(13),
            operation_id=bridge_hex(14),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{"pubkey": disclosure_pubkey}],
        )
        explicit_legacy, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 5,
            bridge_id=bridge_hex(15),
            operation_id=bridge_hex(16),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=[{
                "pubkey": disclosure_pubkey,
                "format": "legacy_audit",
            }],
        )
        assert_equal(legacy_from_pubkeys["bundle"]["view_grants"][0]["format"], "legacy_audit")
        assert_equal(omitted_format_legacy["bundle"]["view_grants"][0]["format"], "legacy_audit")
        assert_equal(explicit_legacy["bundle"]["view_grants"][0]["format"], "legacy_audit")
        omitted_legacy_decrypted = wallet.bridge_decryptviewgrant(
            omitted_format_legacy["bundle"]["view_grants"][0],
            "legacy_audit",
        )
        assert_equal(omitted_legacy_decrypted["format"], "legacy_audit")
        assert_equal(omitted_legacy_decrypted["payload"]["amount"], Decimal("5"))
        assert_equal(omitted_legacy_decrypted["payload"]["recipient_pk_hash"], recipient_info["pk_hash"])

        self.log.info("Disclosure policies should auto-add required grants once the threshold is met")
        policy_grant, _, _ = planin(
            wallet,
            Decimal("5"),
            refund_lock_height + 6,
            bridge_id=bridge_hex(17),
            operation_id=bridge_hex(18),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            disclosure_policy={
                "threshold_amount": Decimal("4"),
                "required_grants": [{
                    "pubkey": disclosure_pubkey,
                    "format": "structured_disclosure",
                    "disclosure_fields": ["amount", "recipient"],
                }],
            },
        )
        assert_equal(policy_grant["bundle"]["view_grant_count"], 1)
        assert_equal(policy_grant["bundle"]["view_grants"][0]["format"], "structured_disclosure")
        assert_equal(policy_grant["bundle"]["view_grants"][0]["disclosure_fields"], ["amount", "recipient"])
        assert_equal(policy_grant["disclosure_policy"]["threshold_amount"], Decimal("4"))

        below_threshold, _, _ = planin(
            wallet,
            Decimal("1"),
            refund_lock_height + 7,
            bridge_id=bridge_hex(19),
            operation_id=bridge_hex(20),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            disclosure_policy={
                "threshold_amount": Decimal("2"),
                "required_grants": [{
                    "pubkey": disclosure_pubkey,
                    "format": "structured_disclosure",
                    "disclosure_fields": ["amount"],
                }],
            },
        )
        assert_equal(below_threshold["bundle"]["view_grant_count"], 0)

        self.log.info("Invalid structured grant inputs should fail with targeted RPC errors")
        invalid_options = {
            "bridge_id": bridge_hex(71),
            "operation_id": bridge_hex(72),
            "refund_lock_height": refund_lock_height + 4,
            "recipient": recipient,
            "operator_view_grants": [{
                "pubkey": disclosure_pubkey,
                "format": "structured_disclosure",
                "disclosure_fields": [],
            }],
        }
        assert_raises_rpc_error(
            -8,
            "operator_view_grants[0].disclosure_fields must not be empty",
            wallet.bridge_planin,
            operator_key,
            refund_key,
            Decimal("1"),
            invalid_options,
        )
        invalid_options["operator_view_grants"][0] = {
            "pubkey": "00",
            "format": "structured_disclosure",
            "disclosure_fields": ["amount"],
        }
        assert_raises_rpc_error(
            -8,
            "operator_view_grants[0].pubkey must be an ML-KEM public key",
            wallet.bridge_planin,
            operator_key,
            refund_key,
            Decimal("1"),
            invalid_options,
        )

        self.log.info("View-grant limits should be enforced across explicit and shorthand inputs")
        max_grant_pubkeys = [disclosure_pubkey, second_disclosure_pubkey]
        while len(max_grant_pubkeys) < 9:
            _, pubkey = get_kem_public_key(wallet)
            max_grant_pubkeys.append(pubkey)
        max_grants = [{
            "pubkey": pubkey,
            "format": "structured_disclosure",
            "disclosure_fields": ["amount"],
        } for pubkey in max_grant_pubkeys[:8]]
        exact_max, _, _ = planin(
            wallet,
            Decimal("2"),
            refund_lock_height + 8,
            bridge_id=bridge_hex(31),
            operation_id=bridge_hex(32),
            recipient=recipient,
            operator_key=operator_key,
            refund_key=refund_key,
            operator_view_grants=max_grants,
        )
        assert_equal(exact_max["bundle"]["view_grant_count"], 8)
        assert_equal(len(exact_max["operator_view_grants"]), 8)
        overflow_options = {
            "bridge_id": bridge_hex(33),
            "operation_id": bridge_hex(34),
            "refund_lock_height": refund_lock_height + 9,
            "recipient": recipient,
            "operator_view_grants": max_grants + [{
                "pubkey": max_grant_pubkeys[8],
                "format": "structured_disclosure",
                "disclosure_fields": ["amount"],
            }],
        }
        assert_raises_rpc_error(
            -8,
            "total bridge view grants exceeds 8 entries",
            wallet.bridge_planin,
            operator_key,
            refund_key,
            Decimal("2"),
            overflow_options,
        )
        mixed_overflow_options = {
            "bridge_id": bridge_hex(35),
            "operation_id": bridge_hex(36),
            "refund_lock_height": refund_lock_height + 10,
            "recipient": recipient,
            "operator_view_pubkeys": max_grant_pubkeys[:8],
            "operator_view_grants": [{
                "pubkey": max_grant_pubkeys[8],
                "format": "structured_disclosure",
                "disclosure_fields": ["amount"],
            }],
        }
        assert_raises_rpc_error(
            -8,
            "total bridge view grants exceeds 8 entries",
            wallet.bridge_planin,
            operator_key,
            refund_key,
            Decimal("2"),
            mixed_overflow_options,
        )

        self.log.info("Omitting recipient should generate a local shielded address")
        generated, _, _ = planin(
            wallet,
            Decimal("1.5"),
            refund_lock_height + 11,
            bridge_id=bridge_hex(21),
            operation_id=bridge_hex(22),
            operator_key=operator_key,
            refund_key=refund_key,
        )
        assert_equal(generated["kind"], "shield")
        assert_equal(generated["recipient_generated"], True)
        assert generated["recipient"].startswith("btxs")

        self.log.info("Pre-fork legacy plan_hex should be rejected when built or submitted after activation")
        mine_addr = wallet.getnewaddress(address_type="p2mr")
        funding_txid = wallet.sendtoaddress(legacy_from_pubkeys["bridge_address"], Decimal("5.00020000"))
        blocks_to_postfork = self.privacy_redesign_height + 1 - node.getblockcount()
        while blocks_to_postfork > 0:
            step = min(blocks_to_postfork, 25)
            mine_block(self, node, mine_addr, blocks=step)
            blocks_to_postfork -= step
        assert node.getblockcount() > self.privacy_redesign_height
        vout, value = find_output(node, funding_txid, legacy_from_pubkeys["bridge_address"], wallet)
        assert_raises_rpc_error(
            -8,
            "accept_plan_view_grants=true",
            wallet.bridge_buildshieldtx,
            legacy_from_pubkeys["plan_hex"],
            funding_txid,
            vout,
            value,
            {"enforce_fee_headroom": False},
        )
        assert_raises_rpc_error(
            -8,
            "accept_plan_view_grants=true",
            wallet.bridge_submitshieldtx,
            legacy_from_pubkeys["plan_hex"],
            funding_txid,
            vout,
            value,
            {"track_pending": False, "enforce_fee_headroom": False},
        )
        assert_raises_rpc_error(
            -8,
            "accept_plan_view_grants=true",
            wallet.bridge_importpending,
            legacy_from_pubkeys["plan_hex"],
            funding_txid,
            vout,
            value,
            {"recover_now": False},
        )
        assert_raises_rpc_error(
            -8,
            "allow_legacy_audit_view_grants=true",
            wallet.bridge_buildshieldtx,
            legacy_from_pubkeys["plan_hex"],
            funding_txid,
            vout,
            value,
            {"enforce_fee_headroom": False, "accept_plan_view_grants": True},
        )
        assert_raises_rpc_error(
            -8,
            "allow_legacy_audit_view_grants=true",
            wallet.bridge_submitshieldtx,
            legacy_from_pubkeys["plan_hex"],
            funding_txid,
            vout,
            value,
            {"track_pending": False, "enforce_fee_headroom": False, "accept_plan_view_grants": True},
        )
        assert_raises_rpc_error(
            -8,
            "allow_legacy_audit_view_grants=true",
            wallet.bridge_importpending,
            legacy_from_pubkeys["plan_hex"],
            funding_txid,
            vout,
            value,
            {"recover_now": False, "accept_plan_view_grants": True},
        )
        imported = wallet.bridge_importpending(
            legacy_from_pubkeys["plan_hex"],
            funding_txid,
            vout,
            value,
            {
                "recover_now": False,
                "accept_plan_view_grants": True,
                "allow_legacy_audit_view_grants": True,
            },
        )
        assert_equal(imported["accepted_plan_view_grants"], True)


if __name__ == "__main__":
    WalletBridgePlanInTest(__file__).main()
