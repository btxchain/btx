#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""decodepsbt coverage for bridge P2MR/CSFS metadata."""

from decimal import Decimal, ROUND_UP

from test_framework.bridge_utils import (
    bridge_hex,
    create_bridge_wallet,
    find_output,
    mine_block,
    planin,
    planout,
    sign_finalize_and_send,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgePsbtTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-regtestshieldedmatrictdisableheight=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_psbt")
        noncanonical_fee_margin = Decimal("0.00001501")
        insufficient_fee_margin = Decimal("0.00005000")
        sufficient_fee_margin = Decimal("0.00020000")

        refund_lock_height = node.getblockcount() + 30
        recipient = wallet.z_getnewaddress()

        self.log.info("Reject postfork bridge-in settlement PSBTs that carry a noncanonical implicit fee bucket")
        noncanonical_plan, _, _ = planin(
            wallet,
            Decimal("1.75"),
            refund_lock_height,
            bridge_id=bridge_hex(18),
            operation_id=bridge_hex(19),
            recipient=recipient,
        )
        noncanonical_txid = wallet.sendtoaddress(
            noncanonical_plan["bridge_address"], Decimal("1.75") + noncanonical_fee_margin
        )
        mine_block(self, node, mine_addr)
        noncanonical_vout, noncanonical_value = find_output(
            node, noncanonical_txid, noncanonical_plan["bridge_address"], wallet
        )
        assert_raises_rpc_error(
            -4,
            "Failed to construct bridge shield settlement PSBT",
            wallet.bridge_buildshieldtx,
            noncanonical_plan["plan_hex"],
            noncanonical_txid,
            noncanonical_vout,
            noncanonical_value,
        )

        self.log.info("Build an underfunded bridge-in settlement PSBT and confirm the RPC marks it before relay rejects it")
        shield_plan, _, _ = planin(
            wallet,
            Decimal("1.75"),
            refund_lock_height,
            bridge_id=bridge_hex(38),
            operation_id=bridge_hex(39),
            recipient=recipient,
        )
        shield_funding_txid = wallet.sendtoaddress(shield_plan["bridge_address"], Decimal("1.75") + insufficient_fee_margin)
        mine_block(self, node, mine_addr)
        shield_vout, shield_value = find_output(node, shield_funding_txid, shield_plan["bridge_address"], wallet)

        shield_built = wallet.bridge_buildshieldtx(shield_plan["plan_hex"], shield_funding_txid, shield_vout, shield_value)
        assert_equal(shield_built["relay_fee_analysis_available"], True)
        assert_equal(shield_built["relay_fee_sufficient"], False)
        assert_equal(shield_built["relay_fee_analysis"]["fee_sufficient"], False)
        assert shield_built["relay_fee_analysis"]["estimated_fee_redacted"]
        assert shield_built["relay_fee_analysis"]["required_total_fee_redacted"]
        assert shield_built["relay_fee_analysis"]["transparent_input_value_redacted"]
        assert shield_built["relay_fee_analysis"]["transparent_output_value_redacted"]
        assert shield_built["relay_fee_analysis"]["shielded_value_balance_redacted"]
        assert shield_built["relay_fee_analysis"]["estimated_fee_bucket"] < shield_built["relay_fee_analysis"]["required_total_fee_bucket"]
        decoded_shield = node.decodepsbt(shield_built["psbt"])
        assert_equal(decoded_shield["inputs"][0]["p2mr_merkle_root"], shield_plan["bridge_root"])
        assert_equal(decoded_shield["inputs"][0]["p2mr_leaf_script"], shield_built["p2mr_leaf_script"])
        assert_equal(decoded_shield["inputs"][0]["p2mr_control_block"], shield_built["p2mr_control_block"])
        assert_equal(decoded_shield["inputs"][0]["p2mr_leaf_hash"], shield_built["p2mr_leaf_hash"])

        shield_signed = wallet.walletprocesspsbt(shield_built["psbt"], True, "ALL", True, False)
        decoded_shield_signed = node.decodepsbt(shield_signed["psbt"])
        assert_equal(len(decoded_shield_signed["inputs"][0]["p2mr_partial_signatures"]), 1)
        assert_equal(decoded_shield_signed["inputs"][0].get("p2mr_csfs_signatures", []), [])
        assert_raises_rpc_error(-26, None, sign_finalize_and_send, wallet, node, shield_built["psbt"])

        self.log.info("Build a safely funded bridge-in settlement PSBT and confirm the relay estimate clears policy")
        funded_shield_plan, _, _ = planin(
            wallet,
            Decimal("1.75"),
            refund_lock_height,
            bridge_id=bridge_hex(138),
            operation_id=bridge_hex(139),
            recipient=recipient,
        )
        funded_shield_txid = wallet.sendtoaddress(funded_shield_plan["bridge_address"], Decimal("1.75") + sufficient_fee_margin)
        mine_block(self, node, mine_addr)
        funded_shield_vout, funded_shield_value = find_output(node, funded_shield_txid, funded_shield_plan["bridge_address"], wallet)
        funded_shield_built = wallet.bridge_buildshieldtx(
            funded_shield_plan["plan_hex"],
            funded_shield_txid,
            funded_shield_vout,
            funded_shield_value,
        )
        assert_equal(funded_shield_built["relay_fee_analysis_available"], True)
        assert_equal(funded_shield_built["relay_fee_sufficient"], True)
        assert funded_shield_built["relay_fee_analysis"]["estimated_fee_redacted"]
        assert funded_shield_built["relay_fee_analysis"]["estimated_fee_bucket"] >= funded_shield_built["relay_fee_analysis"]["required_total_fee_bucket"]
        assert_equal(funded_shield_built["fee_headroom_enforced"], False)
        assert_equal(funded_shield_built["fee_headroom_sufficient"], True)

        self.log.info("Bridge-in shield settlement headroom can warn at build time and enforce at submit time")
        headroom_probe_plan, _, _ = planin(
            wallet,
            Decimal("1.75"),
            refund_lock_height,
            bridge_id=bridge_hex(0x238),
            operation_id=bridge_hex(0x239),
            recipient=recipient,
        )
        headroom_probe_txid = wallet.sendtoaddress(
            headroom_probe_plan["bridge_address"],
            Decimal("1.75") + sufficient_fee_margin,
        )
        mine_block(self, node, mine_addr)
        headroom_probe_vout, headroom_probe_value = find_output(
            node, headroom_probe_txid, headroom_probe_plan["bridge_address"], wallet
        )
        headroom_probe_built = wallet.bridge_buildshieldtx(
            headroom_probe_plan["plan_hex"],
            headroom_probe_txid,
            headroom_probe_vout,
            headroom_probe_value,
        )
        required_total_fee = Decimal(str(headroom_probe_built["relay_fee_analysis"]["required_total_fee_bucket"]))
        headroom_margin = (required_total_fee * Decimal("1.5")).quantize(Decimal("0.00000001"), rounding=ROUND_UP)

        headroom_plan, _, _ = planin(
            wallet,
            Decimal("1.75"),
            refund_lock_height,
            bridge_id=bridge_hex(0x338),
            operation_id=bridge_hex(0x339),
            recipient=recipient,
        )
        headroom_txid = wallet.sendtoaddress(
            headroom_plan["bridge_address"],
            Decimal("1.75") + headroom_margin,
        )
        mine_block(self, node, mine_addr)
        headroom_vout, headroom_value = find_output(node, headroom_txid, headroom_plan["bridge_address"], wallet)
        headroom_built = wallet.bridge_buildshieldtx(
            headroom_plan["plan_hex"],
            headroom_txid,
            headroom_vout,
            headroom_value,
        )
        assert_equal(headroom_built["relay_fee_analysis_available"], True)
        assert_equal(headroom_built["relay_fee_sufficient"], True)
        assert_equal(headroom_built["fee_headroom_enforced"], False)
        assert_equal(headroom_built["fee_headroom_sufficient"], False)
        assert headroom_built["relay_fee_analysis"]["estimated_fee_redacted"]
        assert headroom_built["relay_fee_analysis"]["required_total_fee_redacted"]
        assert headroom_built["relay_fee_analysis"]["required_fee_headroom_redacted"]
        assert headroom_built["relay_fee_analysis"]["estimated_fee_bucket"] >= headroom_built["relay_fee_analysis"]["required_total_fee_bucket"]
        assert headroom_built["relay_fee_analysis"]["estimated_fee_bucket"] < headroom_built["relay_fee_analysis"]["required_fee_headroom_bucket"]
        assert_raises_rpc_error(
            -4,
            "Bridge fee headroom too low",
            wallet.bridge_buildshieldtx,
            headroom_plan["plan_hex"],
            headroom_txid,
            headroom_vout,
            headroom_value,
            {"enforce_fee_headroom": True},
        )
        assert_raises_rpc_error(
            -4,
            "Bridge fee headroom too low",
            wallet.bridge_submitshieldtx,
            headroom_plan["plan_hex"],
            headroom_txid,
            headroom_vout,
            headroom_value,
        )
        submitted_headroom = wallet.bridge_submitshieldtx(
            headroom_plan["plan_hex"],
            headroom_txid,
            headroom_vout,
            headroom_value,
            {"enforce_fee_headroom": False},
        )
        assert submitted_headroom["txid"] in node.getrawmempool()
        assert_equal(submitted_headroom["fee_headroom_enforced"], False)
        assert_equal(submitted_headroom["fee_headroom_sufficient"], False)
        mine_block(self, node, mine_addr)

        payout_address = wallet.getnewaddress(address_type="p2mr")
        plan, _, _ = planout(
            wallet,
            payout_address,
            Decimal("2"),
            refund_lock_height,
            bridge_id=bridge_hex(40),
            operation_id=bridge_hex(41),
        )

        funding_txid = wallet.sendtoaddress(plan["bridge_address"], Decimal("2") + sufficient_fee_margin)
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, plan["bridge_address"], wallet)

        self.log.info("Build an unshield settlement PSBT and inspect the selected CTV+CSFS metadata")
        built = wallet.bridge_buildunshieldtx(plan["plan_hex"], funding_txid, vout, value)
        assert_equal(built["relay_fee_analysis_available"], True)
        assert_equal(built["relay_fee_sufficient"], True)
        assert built["relay_fee_analysis"]["estimated_fee_redacted"]
        assert built["relay_fee_analysis"]["required_total_fee_redacted"]
        decoded = node.decodepsbt(built["psbt"])
        assert_equal(decoded["inputs"][0]["p2mr_merkle_root"], plan["bridge_root"])
        assert_equal(decoded["inputs"][0]["p2mr_leaf_script"], built["p2mr_leaf_script"])
        assert_equal(decoded["inputs"][0]["p2mr_control_block"], built["p2mr_control_block"])
        assert_equal(decoded["inputs"][0]["p2mr_leaf_hash"], built["p2mr_leaf_hash"])
        assert_equal(len(decoded["inputs"][0]["p2mr_csfs_messages"]), 1)
        assert_equal(decoded["inputs"][0]["p2mr_csfs_messages"][0]["message"], plan["attestation"]["bytes"])

        self.log.info("Signing should populate CSFS attestation signatures for the attested unshield path")
        signed = wallet.walletprocesspsbt(built["psbt"], True, "ALL", True, False)
        decoded_signed = node.decodepsbt(signed["psbt"])
        assert_equal(decoded_signed["inputs"][0].get("p2mr_partial_signatures", []), [])
        assert_equal(len(decoded_signed["inputs"][0]["p2mr_csfs_signatures"]), 1)
        assert_equal(decoded_signed["inputs"][0]["p2mr_csfs_messages"][0]["message"], plan["attestation"]["bytes"])


if __name__ == "__main__":
    WalletBridgePsbtTest(__file__).main()
