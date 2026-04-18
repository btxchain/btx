#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for signed bridge batch authorizations and batch commitment planning."""

import base64
from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    create_bridge_wallet,
    find_output,
    mine_block,
    planbatchout,
    planout,
    sign_batch_authorization,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeBatchCommitmentTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_batch")
        fee_margin = Decimal("0.00100000")

        refund_lock_height = node.getblockcount() + 25
        bridge_id = bridge_hex(0x500)
        operation_id = bridge_hex(0x501)
        payout_amounts = [Decimal("1.25"), Decimal("1.50"), Decimal("1.75")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        authorizer_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]

        self.log.info("Sign wallet-backed bridge batch authorizations and confirm canonical decoding")
        authorizations = []
        raw_leaves = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                authorizer_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x600 + index),
                    "destination_id": bridge_hex(0x700 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x800 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            decoded = wallet.bridge_decodebatchauthorization(signed["authorization_hex"])
            assert_equal(decoded["authorization_hash"], signed["authorization_hash"])
            assert_equal(decoded["leaf"], signed["leaf"])
            assert_equal(decoded["verified"], True)
            authorizations.append(signed)
            raw_leaves.append(signed["leaf"])
            payouts.append({"address": payout_addresses[index], "amount": amount})

        self.log.info("Build the same batch commitment from signed authorizations and from explicit leaves")
        commitment_from_auth = build_batch_commitment(
            wallet,
            "bridge_out",
            [{"authorization_hex": item["authorization_hex"]} for item in authorizations],
            bridge_id=bridge_id,
            operation_id=operation_id,
        )
        commitment_from_leaves = build_batch_commitment(
            wallet,
            "bridge_out",
            raw_leaves,
            bridge_id=bridge_id,
            operation_id=operation_id,
        )
        decoded_commitment = wallet.bridge_decodebatchcommitment(commitment_from_auth["commitment_hex"])

        assert_equal(commitment_from_auth["commitment_hash"], commitment_from_leaves["commitment_hash"])
        assert_equal(commitment_from_auth["commitment_hash"], decoded_commitment["commitment_hash"])
        assert_equal(commitment_from_auth["commitment"]["entry_count"], len(authorizations))
        assert_equal(len(commitment_from_auth["authorizations"]), len(authorizations))

        self.log.info("Compare one batch bridge-out settlement against many single bridge-out settlements")
        batch_plan, operator_key, refund_key = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=operation_id,
            batch_commitment_hex=commitment_from_auth["commitment_hex"],
        )
        total_amount = sum(payout_amounts, Decimal("0"))
        batch_psbt = wallet.bridge_buildunshieldtx(batch_plan["plan_hex"], bridge_hex(0x900), 0, total_amount)

        assert_equal(batch_plan["attestation"]["message"]["version"], 2)
        assert_equal(batch_plan["attestation"]["message"]["batch_entry_count"], len(authorizations))
        assert_equal(batch_plan["attestation"]["message"]["batch_root"], commitment_from_auth["commitment"]["batch_root"])

        batch_plan_bytes = len(bytes.fromhex(batch_plan["plan_hex"]))
        batch_psbt_bytes = len(base64.b64decode(batch_psbt["psbt"]))
        batch_attestation_bytes = len(bytes.fromhex(batch_plan["attestation"]["bytes"]))

        single_plan_bytes = 0
        single_psbt_bytes = 0
        single_attestation_bytes = 0
        for index, amount in enumerate(payout_amounts):
            single_plan, _, _ = planout(
                wallet,
                payout_addresses[index],
                amount,
                refund_lock_height,
                bridge_id=bridge_id,
                operation_id=bridge_hex(0xA00 + index),
                operator_key=operator_key,
                refund_key=refund_key,
            )
            single_psbt = wallet.bridge_buildunshieldtx(single_plan["plan_hex"], bridge_hex(0xB00 + index), 0, amount)
            single_plan_bytes += len(bytes.fromhex(single_plan["plan_hex"]))
            single_psbt_bytes += len(base64.b64decode(single_psbt["psbt"]))
            single_attestation_bytes += len(bytes.fromhex(single_plan["attestation"]["bytes"]))

        assert batch_plan_bytes < single_plan_bytes
        assert batch_psbt_bytes < single_psbt_bytes
        assert batch_attestation_bytes < single_attestation_bytes

        self.log.info("Fund and submit the aggregated bridge-out settlement through the wallet RPC")
        funding_txid = wallet.sendtoaddress(batch_plan["bridge_address"], total_amount + fee_margin)
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, batch_plan["bridge_address"], wallet)
        submitted = wallet.bridge_submitunshieldtx(batch_plan["plan_hex"], funding_txid, vout, value)
        assert_equal(submitted["selected_path"], "normal")
        assert_equal(submitted["bridge_root"], batch_plan["bridge_root"])
        assert_equal(submitted["ctv_hash"], batch_plan["ctv_hash"])
        mine_block(self, node, mine_addr)
        for index, amount in enumerate(payout_amounts):
            assert_equal(Decimal(str(wallet.getreceivedbyaddress(payout_addresses[index]))), amount)

        self.log.info(
            "Batch compression observed: plan %d -> %d bytes, attestation %d -> %d bytes, psbt %d -> %d bytes",
            single_plan_bytes,
            batch_plan_bytes,
            single_attestation_bytes,
            batch_attestation_bytes,
            single_psbt_bytes,
            batch_psbt_bytes,
        )


if __name__ == "__main__":
    WalletBridgeBatchCommitmentTest(__file__).main()
