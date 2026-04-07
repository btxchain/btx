#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for aggregated bridge-in planning from signed authorizations."""

import base64
from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    create_bridge_wallet,
    find_output,
    mine_block,
    planbatchin,
    planin,
    sign_batch_authorization,
)
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeBatchInTest(BitcoinTestFramework):
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
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_batchin")
        fee_margin = Decimal("0.00040000")
        node.createwallet(wallet_name="bridge_batchin_recipient", descriptors=True)
        recipient_wallet = encrypt_and_unlock_wallet(node, "bridge_batchin_recipient")

        recipient = recipient_wallet.z_getnewaddress()
        refund_lock_height = node.getblockcount() + 20
        bridge_id = bridge_hex(0x1100)
        operation_id = bridge_hex(0x1101)
        credit_amounts = [Decimal("1.25"), Decimal("1.50"), Decimal("1.75")]
        authorizer_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in credit_amounts]

        self.log.info("Sign bridge-in authorizations that represent off-chain shield credits")
        authorization_entries = []
        for index, amount in enumerate(credit_amounts):
            signed = sign_batch_authorization(
                wallet,
                authorizer_addresses[index],
                "bridge_in",
                {
                    "kind": "shield_credit",
                    "wallet_id": bridge_hex(0x1200 + index),
                    "destination_id": bridge_hex(0x1300 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x1400 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            authorization_entries.append({"authorization_hex": signed["authorization_hex"]})

        self.log.info("Plan one aggregated bridge-in settlement note and compare it with many single notes")
        batch_commitment = build_batch_commitment(
            wallet,
            "bridge_in",
            authorization_entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
        )
        batch_plan, operator_key, refund_key = planbatchin(
            wallet,
            authorization_entries,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=operation_id,
            recipient=recipient,
        )

        assert_equal(batch_plan["kind"], "shield")
        assert_equal(batch_plan["recipient"], recipient)
        assert_equal(batch_plan["recipient_generated"], False)
        assert_equal(batch_plan["bundle"]["shielded_output_count"], 1)
        assert_equal(batch_plan["batch_commitment_hex"], batch_commitment["commitment_hex"])
        assert_equal(batch_plan["batch_commitment_hash"], batch_commitment["commitment_hash"])
        assert_equal(batch_plan["batch_commitment"]["entry_count"], len(authorization_entries))

        total_amount = sum(credit_amounts, Decimal("0"))
        batch_psbt = wallet.bridge_buildshieldtx(batch_plan["plan_hex"], bridge_hex(0x1500), 0, total_amount)
        batch_plan_bytes = len(bytes.fromhex(batch_plan["plan_hex"]))
        batch_psbt_bytes = len(base64.b64decode(batch_psbt["psbt"]))

        single_plan_bytes = 0
        single_psbt_bytes = 0
        for index, amount in enumerate(credit_amounts):
            single_plan, _, _ = planin(
                wallet,
                amount,
                refund_lock_height,
                bridge_id=bridge_id,
                operation_id=bridge_hex(0x1600 + index),
                recipient=recipient,
                operator_key=operator_key,
                refund_key=refund_key,
            )
            single_psbt = wallet.bridge_buildshieldtx(single_plan["plan_hex"], bridge_hex(0x1700 + index), 0, amount)
            single_plan_bytes += len(bytes.fromhex(single_plan["plan_hex"]))
            single_psbt_bytes += len(base64.b64decode(single_psbt["psbt"]))

        assert batch_plan_bytes < single_plan_bytes
        assert batch_psbt_bytes < single_psbt_bytes

        self.log.info("Fund and submit the aggregated bridge-in settlement through the wallet RPC")
        funding_txid = wallet.sendtoaddress(batch_plan["bridge_address"], total_amount + fee_margin)
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, batch_plan["bridge_address"], wallet)
        submitted = wallet.bridge_submitshieldtx(batch_plan["plan_hex"], funding_txid, vout, value)
        assert_equal(submitted["selected_path"], "normal")
        assert_equal(submitted["bridge_root"], batch_plan["bridge_root"])
        assert_equal(submitted["ctv_hash"], batch_plan["ctv_hash"])
        mine_block(self, node, mine_addr)
        assert_equal(Decimal(recipient_wallet.z_getbalance()["balance"]), total_amount)

        self.log.info(
            "Batch bridge-in compression observed: plan %d -> %d bytes, psbt %d -> %d bytes",
            single_plan_bytes,
            batch_plan_bytes,
            single_psbt_bytes,
            batch_psbt_bytes,
        )


if __name__ == "__main__":
    WalletBridgeBatchInTest(__file__).main()
