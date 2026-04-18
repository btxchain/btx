#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for committed verifier sets over bridge batch statements."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_batch_commitment,
    build_batch_statement,
    build_external_anchor,
    build_verifier_set,
    create_bridge_wallet,
    export_bridge_key,
    planbatchout,
    sign_batch_authorization,
    sign_batch_receipt,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBridgeVerifierSetTest(BitcoinTestFramework):
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
        wallet, _ = create_bridge_wallet(self, node, wallet_name="bridge_verifier_set")

        refund_lock_height = node.getblockcount() + 30
        expected_source = {
            "domain_id": bridge_hex(0x4100),
            "source_epoch": 23,
            "data_root": bridge_hex(0x4101),
        }

        bridge_id = bridge_hex(0x4200)
        operation_id = bridge_hex(0x4201)
        payout_amounts = [Decimal("1.20"), Decimal("1.35"), Decimal("1.50")]
        payout_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        user_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in payout_amounts]
        attestor_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in range(3)]
        outsider_address = wallet.getnewaddress(address_type="p2mr")

        self.log.info("Build one committed verifier set for a bridge-out batch statement")
        attestors = [export_bridge_key(wallet, address, "ml-dsa-44") for address in attestor_addresses]
        verifier_set = build_verifier_set(wallet, attestors, required_signers=2)
        assert_equal(verifier_set["verifier_set"]["attestor_count"], 3)
        assert_equal(verifier_set["verifier_set"]["required_signers"], 2)

        entries = []
        payouts = []
        for index, amount in enumerate(payout_amounts):
            signed = sign_batch_authorization(
                wallet,
                user_addresses[index],
                "bridge_out",
                {
                    "kind": "transparent_payout",
                    "wallet_id": bridge_hex(0x4300 + index),
                    "destination_id": bridge_hex(0x4400 + index),
                    "amount": amount,
                    "authorization_nonce": bridge_hex(0x4500 + index),
                },
                bridge_id=bridge_id,
                operation_id=operation_id,
            )
            entries.append({"authorization_hex": signed["authorization_hex"]})
            payouts.append({"address": payout_addresses[index], "amount": amount})

        statement = build_batch_statement(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            domain_id=expected_source["domain_id"],
            source_epoch=expected_source["source_epoch"],
            data_root=expected_source["data_root"],
            verifier_set=verifier_set["verifier_set"],
        )
        assert_equal(statement["statement"]["version"], 2)
        assert_equal(statement["statement"]["verifier_set"], verifier_set["verifier_set"])

        self.log.info("Build compact membership proofs for the receipt subset")
        targeted_verifier_set = build_verifier_set(
            wallet,
            attestors,
            required_signers=2,
            targets=attestors[:2],
        )
        proof_hexes = [entry["proof_hex"] for entry in targeted_verifier_set["proofs"]]
        assert_equal(targeted_verifier_set["verifier_set"], verifier_set["verifier_set"])
        assert_equal(len(proof_hexes), 2)

        self.log.info("Require verifier-set membership proofs when deriving the external anchor")
        receipts = [
            sign_batch_receipt(wallet, attestor_addresses[0], statement["statement_hex"])["receipt_hex"],
            sign_batch_receipt(wallet, attestor_addresses[1], statement["statement_hex"])["receipt_hex"],
        ]
        external_anchor = build_external_anchor(
            wallet,
            statement["statement_hex"],
            receipts,
            {
                "attestor_proofs": proof_hexes,
            },
        )
        assert_equal(external_anchor["verifier_set"], verifier_set["verifier_set"])
        assert_equal(external_anchor["distinct_attestor_count"], 2)
        assert_equal(external_anchor["receipt_count"], 2)

        fallback_anchor = build_external_anchor(
            wallet,
            statement["statement_hex"],
            receipts,
            {
                "revealed_attestors": attestors,
            },
        )
        assert_equal(fallback_anchor["external_anchor"], external_anchor["external_anchor"])

        assert_raises_rpc_error(
            -8,
            "statement requires options.attestor_proofs or options.revealed_attestors to validate verifier_set membership",
            wallet.bridge_buildexternalanchor,
            statement["statement_hex"],
            receipts,
            {},
        )
        assert_raises_rpc_error(
            -8,
            "receipt set does not satisfy statement verifier_set",
            wallet.bridge_buildexternalanchor,
            statement["statement_hex"],
            [receipts[0]],
            {"attestor_proofs": [proof_hexes[0]]},
        )
        assert_raises_rpc_error(
            -8,
            "options.attestor_proofs must contain one proof per receipt",
            wallet.bridge_buildexternalanchor,
            statement["statement_hex"],
            receipts,
            {"attestor_proofs": [proof_hexes[0]]},
        )

        outsider_receipt = sign_batch_receipt(wallet, outsider_address, statement["statement_hex"])["receipt_hex"]
        assert_raises_rpc_error(
            -8,
            "options.attestor_proofs[1] does not verify for receipts[1].attestor",
            wallet.bridge_buildexternalanchor,
            statement["statement_hex"],
            [receipts[0], outsider_receipt],
            {"attestor_proofs": proof_hexes},
        )

        self.log.info("Feed the verified external anchor into the existing batch commitment and settlement path")
        anchored_commitment = build_batch_commitment(
            wallet,
            "bridge_out",
            entries,
            bridge_id=bridge_id,
            operation_id=operation_id,
            external_anchor=external_anchor["external_anchor"],
        )
        batch_out_plan, _, _ = planbatchout(
            wallet,
            payouts,
            refund_lock_height,
            bridge_id=bridge_id,
            operation_id=operation_id,
            batch_commitment_hex=anchored_commitment["commitment_hex"],
        )
        assert_equal(batch_out_plan["attestation"]["message"]["version"], 3)
        assert_equal(batch_out_plan["attestation"]["message"]["external_anchor"], external_anchor["external_anchor"])

        self.log.info(
            "Verifier-set surfaces observed: statement %d bytes, proof %d bytes, verifier_set root %s",
            len(bytes.fromhex(statement["statement_hex"])),
            len(bytes.fromhex(proof_hexes[0])),
            verifier_set["verifier_set"]["attestor_root"],
        )


if __name__ == "__main__":
    WalletBridgeVerifierSetTest(__file__).main()
