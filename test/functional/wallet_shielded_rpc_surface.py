#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.bridge_utils import (
    bridge_hex,
    build_egress_batch_tx,
    build_egress_statement,
    build_hybrid_anchor,
    build_ingress_batch_tx,
    build_ingress_statement,
    build_proof_anchor,
    build_proof_policy,
    build_proof_profile,
    build_proof_receipt,
    build_verifier_set,
    export_bridge_key,
    sign_batch_receipt,
)
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

LIVE_DIRECT_LIMIT = 8


class WalletShieldedRpcSurfaceTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0"]]
        # The functional harness halves this value for RPC client timeouts.
        # Keep enough headroom for shielded setup mining on slower Linux containers.
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        node.createwallet(wallet_name="depositonly", descriptors=True)
        node.createwallet(wallet_name="funding", descriptors=True)
        node.createwallet(wallet_name="ingress", descriptors=True)
        node.createwallet(wallet_name="ingress_multishard", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        deposit_wallet = encrypt_and_unlock_wallet(node, "depositonly")
        funding_wallet = node.get_wallet_rpc("funding")
        ingress_wallet = encrypt_and_unlock_wallet(node, "ingress")
        ingress_multishard_wallet = encrypt_and_unlock_wallet(node, "ingress_multishard")

        self.log.info("Edge case: z_shieldcoinbase rejects when no mature coinbase exists")
        assert_raises_rpc_error(-4, "No mature coinbase outputs available", wallet.z_shieldcoinbase)

        self.log.info("Fallback path: z_sendmany deposits directly from transparent funds when shielded balance is insufficient")
        funding_mine_addr = funding_wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, funding_wallet, funding_mine_addr, Decimal("2.0"), maturity_blocks=101, sync_fun=self.no_op
        )
        deposit_taddr = deposit_wallet.getnewaddress()
        funding_wallet.sendtoaddress(deposit_taddr, Decimal("1.0"))
        self.generatetoaddress(node, 1, funding_mine_addr, sync_fun=self.no_op)
        fallback_dest = deposit_wallet.z_getnewaddress()
        fallback_send = deposit_wallet.z_sendmany([{"address": fallback_dest, "amount": Decimal("0.75")}])
        assert fallback_send["txid"] in node.getrawmempool()
        assert_equal(fallback_send["spends"], 0)
        assert_greater_than(fallback_send["outputs"], 0)
        fallback_view = deposit_wallet.z_viewtransaction(fallback_send["txid"])
        assert_equal(fallback_view["family"], "v2_send")
        assert_equal(len(fallback_view["spends"]), 0)
        assert_equal(fallback_view["output_chunks"], [])
        assert any(output["amount"] == Decimal("0.75") and output["is_ours"] for output in fallback_view["outputs"])
        self.generatetoaddress(node, 1, funding_mine_addr, sync_fun=self.no_op)
        fallback_notes = deposit_wallet.z_listunspent(1, 9999999, False)
        assert any(note["amount"] == Decimal("0.75") for note in fallback_notes)

        mine_addr = wallet.getnewaddress()
        self.generatetoaddress(node, 130, mine_addr, sync_fun=self.no_op)

        self.log.info("Fund a trusted transparent balance and shield it")
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("6.0"), sync_fun=self.no_op
        )
        z_coinbase = wallet.z_getnewaddress()
        shield_plan = wallet.z_planshieldfunds(Decimal("5.0"), z_coinbase)
        assert shield_plan["estimated_chunk_count"] >= 1
        assert shield_plan["policy"]["recommended_max_inputs_per_chunk"] >= 1
        assert shield_plan["policy"]["selection_strategy"] == "largest-first"
        shield_cb = wallet.z_shieldfunds(Decimal("5.0"), z_coinbase)
        shield_cb_txid = shield_cb["txid"]
        assert shield_cb_txid in node.getrawmempool()
        assert_greater_than(shield_cb["transparent_inputs"], 0)

        view_cb = wallet.z_viewtransaction(shield_cb_txid)
        assert view_cb["family"] == "v2_send"
        assert len(view_cb["outputs"]) >= 1
        assert_equal(view_cb["output_chunks"], [])
        assert "value_balance" in view_cb
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        bal = wallet.z_getbalance()
        assert_greater_than(Decimal(bal["balance"]), Decimal("0"))
        assert_greater_than(int(bal["note_count"]), 0)

        self.log.info("Seed commitment tree to satisfy ring diversity for spend proofs")
        min_ring_notes = 16
        notes_to_add = max(0, min_ring_notes - int(bal["note_count"]))
        for _ in range(notes_to_add):
            try:
                seed_res = wallet.z_shieldfunds(Decimal("0.5"), z_coinbase)
            except JSONRPCException as e:
                if e.error.get("code") == -6:
                    break
                raise
            assert seed_res["chunk_count"] == 1
            assert len(seed_res["txids"]) == 1
            assert seed_res["txids"][0] == seed_res["txid"]
            assert seed_res["policy"]["recommended_max_inputs_per_chunk"] >= 1
            assert seed_res["txid"] in node.getrawmempool()
        if notes_to_add:
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        seeded = wallet.z_getbalance()
        assert_greater_than(int(seeded["note_count"]), min_ring_notes - 1)

        self.log.info("Zero-conf shielded accounting should include local mempool outputs and exclude pending spends")
        zero_conf_dest = wallet.z_getnewaddress()
        zero_conf_send = wallet.z_sendmany([{"address": zero_conf_dest, "amount": Decimal("0.33")}])
        assert zero_conf_send["txid"] in node.getrawmempool()
        sender_zero_conf = wallet.z_getbalance(0)
        assert_greater_than_or_equal(Decimal(sender_zero_conf["balance"]), Decimal("0"))
        assert_equal(Decimal(sender_zero_conf["balance"]), Decimal(seeded["balance"]) - zero_conf_send["fee"])
        assert any(note["amount"] == Decimal("0.33") for note in wallet.z_listunspent(0, 9999999, False))
        assert not any(note["amount"] == Decimal("0.33") for note in wallet.z_listunspent(1, 9999999, False))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert any(note["amount"] == Decimal("0.33") for note in wallet.z_listunspent(1, 9999999, False))

        self.log.info("Edge cases: parameter and funding validation")
        assert_raises_rpc_error(-8, "Amount must be positive", wallet.z_shieldfunds, Decimal("0"))
        assert_raises_rpc_error(-6, "Insufficient transparent funds", wallet.z_shieldfunds, Decimal("1000000"))
        assert_raises_rpc_error(-8, "Amount must be positive", wallet.z_planshieldfunds, Decimal("0"))
        assert_raises_rpc_error(-6, "Insufficient transparent funds", wallet.z_planshieldfunds, Decimal("1000000"), z_coinbase)
        assert_raises_rpc_error(-5, "Transaction not found or no shielded bundle", wallet.z_viewtransaction, "00" * 32)

        too_many_recipients = []
        for _ in range(17):
            too_many_recipients.append({"address": wallet.z_getnewaddress(), "amount": Decimal("0.01")})
        assert_raises_rpc_error(-8, "Too many shielded recipients", wallet.z_sendmany, too_many_recipients)
        assert_raises_rpc_error(-5, "Invalid shielded destination", wallet.z_sendtoaddress, wallet.getnewaddress(), Decimal("0.1"))

        self.log.info("Happy path: z_sendtoaddress stays on the v2 private send path and preserves wallet metadata")
        sendto_target = wallet.z_getnewaddress()
        sendto_result = wallet.z_sendtoaddress(
            sendto_target,
            Decimal("0.25"),
            "slice17 sendtoaddress",
            "internal recipient",
            True,
            None,
            True,
            6,
            "economical",
        )
        assert sendto_result["txid"] in node.getrawmempool()
        assert_equal(sendto_result["family"], "v2_send")
        assert_greater_than(sendto_result["fee"], Decimal("0"))
        assert_greater_than(sendto_result["fee"], Decimal("0.0001"))
        assert sendto_result["fee"] in {
            Decimal("0.0004"),
            Decimal("0.0008"),
            Decimal("0.0016"),
            Decimal("0.0032"),
            Decimal("0.0064"),
        }
        assert_greater_than(sendto_result["spends"], 0)
        assert_greater_than(sendto_result["outputs"], 0)
        sendto_view = wallet.z_viewtransaction(sendto_result["txid"])
        assert_equal(sendto_view["family"], "v2_send")
        assert_equal(sendto_view["output_chunks"], [])
        expected_sendto_amount = Decimal("0.25") - sendto_result["fee"]
        assert any(output["amount"] == expected_sendto_amount and output["is_ours"] for output in sendto_view["outputs"])
        sendto_wallet_tx = wallet.gettransaction(sendto_result["txid"])
        assert_equal(sendto_wallet_tx["comment"], "slice17 sendtoaddress")
        assert_equal(sendto_wallet_tx["to"], "internal recipient")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Happy path: z_sendmany can subtract fee from multiple shielded recipients")
        split_dest_a = wallet.z_getnewaddress()
        split_dest_b = wallet.z_getnewaddress()
        split_fee = Decimal("0.00160001")
        split_send = wallet.z_sendmany(
            [
                {"address": split_dest_a, "amount": Decimal("0.30")},
                {"address": split_dest_b, "amount": Decimal("0.20")},
            ],
            split_fee,
            [0, 1],
        )
        assert split_send["txid"] in node.getrawmempool()
        assert_equal(split_send["fee"], split_fee)
        split_view = wallet.z_viewtransaction(split_send["txid"])
        assert any(output["amount"] == Decimal("0.29919999") and output["is_ours"] for output in split_view["outputs"])
        assert any(output["amount"] == Decimal("0.1992") and output["is_ours"] for output in split_view["outputs"])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Happy path: z_shieldcoinbase accepts smart-fee controls")
        shielded_coinbase = wallet.z_shieldcoinbase(wallet.z_getnewaddress(), None, 1, 6, "economical")
        assert shielded_coinbase["txid"] in node.getrawmempool()
        assert_greater_than(shielded_coinbase["amount"], Decimal("0"))
        assert_equal(shielded_coinbase["shielding_inputs"], 1)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Happy path: z_shieldcoinbase caps oversized batches to the SMILE note limit instead of overbuilding")
        capped_coinbase = wallet.z_shieldcoinbase(wallet.z_getnewaddress(), None, 50, 6, "economical")
        assert capped_coinbase["txid"] in node.getrawmempool()
        assert_greater_than(capped_coinbase["amount"], Decimal("0"))
        assert_greater_than(capped_coinbase["shielding_inputs"], 1)
        assert capped_coinbase["shielding_inputs"] <= 50
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Create additional shielded notes to exercise merge and view RPCs")
        merge_target = wallet.z_getnewaddress()
        for i in range(2):
            shield_res = wallet.z_sendmany([{"address": merge_target, "amount": Decimal("0.2")}])
            assert shield_res["txid"] in node.getrawmempool()
            assert_greater_than(shield_res["spends"], 0)
            assert_greater_than(shield_res["outputs"], 0)
            if i == 0:
                send_view = wallet.z_viewtransaction(shield_res["txid"])
                assert send_view["family"] == "v2_send"
                assert_equal(send_view["output_chunks"], [])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        notes_before = wallet.z_listunspent(1, 9999999, False)
        assert len(notes_before) >= 3

        self.log.info("Edge case: z_mergenotes enforces minimum note count parameter")
        assert_raises_rpc_error(-8, "max_notes must be at least 2", wallet.z_mergenotes, 1)

        self.log.info("Happy path: merge notes and verify transaction view semantics")
        merge = None
        for attempt in range(3):
            try:
                merge = wallet.z_mergenotes(2)
                break
            except JSONRPCException as e:
                if e.error.get("code") != -4 or "No merge candidate notes found" not in e.error.get("message", ""):
                    raise
                self.log.info("Merge candidate set unavailable (attempt %d), creating one more note", attempt + 1)
                shield_res = wallet.z_sendmany([{"address": merge_target, "amount": Decimal("0.1")}])
                assert shield_res["txid"] in node.getrawmempool()
                self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert merge is not None
        merge_txid = merge["txid"]
        assert merge_txid in node.getrawmempool()
        assert_greater_than(merge["merged_notes"], 1)

        merge_view = wallet.z_viewtransaction(merge_txid)
        assert merge_view["family"] == "v2_send"
        assert len(merge_view["spends"]) >= 1
        assert len(merge_view["outputs"]) >= 1
        assert_equal(merge_view["output_chunks"], [])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        notes_after = wallet.z_listunspent(1, 9999999, False)
        assert len(notes_after) >= 1

        self.log.info("Fallback path: z_mergenotes avoids a fee-insufficient tiny-note prefix when a viable live merge set exists")
        node.createwallet(wallet_name="mergefallback", descriptors=True)
        mergefallback = encrypt_and_unlock_wallet(node, "mergefallback")
        mergefallback_addr = mergefallback.z_getnewaddress()
        for _ in range(LIVE_DIRECT_LIMIT):
            dust_send = wallet.z_sendmany([{"address": mergefallback_addr, "amount": Decimal("0.00000100")}])
            assert dust_send["txid"] in node.getrawmempool()
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        for _ in range(2):
            large_send = wallet.z_sendmany([{"address": mergefallback_addr, "amount": Decimal("0.20")}])
            assert large_send["txid"] in node.getrawmempool()
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(int(mergefallback.z_getbalance()["note_count"]), LIVE_DIRECT_LIMIT + 2)
        mergefallback_merge = mergefallback.z_mergenotes(LIVE_DIRECT_LIMIT)
        assert mergefallback_merge["txid"] in node.getrawmempool()
        assert_equal(mergefallback_merge["merged_notes"], LIVE_DIRECT_LIMIT)
        assert_equal(mergefallback.z_viewtransaction(mergefallback_merge["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Build-only bridge egress RPCs return canonical wallet-visible chunk metadata")
        egress_recipients = [
            {"address": wallet.z_getnewaddress(), "amount": Decimal("0.11")},
            {"address": wallet.z_getnewaddress(), "amount": Decimal("0.12")},
        ]
        proof_profile = build_proof_profile(
            wallet,
            family="shieldedegress",
            proof_type="receipt",
            claim_system="settlement",
        )
        descriptor = {
            "proof_system_id": proof_profile["proof_system_id"],
            "verifier_key_hash": bridge_hex(0x91),
        }
        proof_policy = build_proof_policy(wallet, [descriptor], required_receipts=1, targets=[descriptor])
        egress_statement = build_egress_statement(
            wallet,
            egress_recipients,
            bridge_id=bridge_hex(0x81),
            operation_id=bridge_hex(0x82),
            domain_id=bridge_hex(0x83),
            source_epoch=9,
            data_root=bridge_hex(0x84),
            proof_policy=proof_policy["proof_policy"],
        )
        proof_receipt = build_proof_receipt(
            wallet,
            egress_statement["statement_hex"],
            proof_profile_hex=proof_profile["profile_hex"],
            verifier_key_hash=descriptor["verifier_key_hash"],
            public_values_hash=bridge_hex(0x85),
            proof_commitment=bridge_hex(0x86),
        )
        egress_tx = build_egress_batch_tx(
            wallet,
            egress_statement["statement_hex"],
            [descriptor],
            [proof_receipt["proof_receipt_hex"]],
            egress_recipients,
        )
        assert_equal(egress_tx["family"], "v2_egress_batch")
        assert_equal(egress_tx["statement_hash"], egress_statement["statement_hash"])
        assert_equal(egress_tx["descriptor_count"], 1)
        assert_equal(egress_tx["proof_receipt_count"], 1)
        assert_equal(len(egress_tx["outputs"]), 2)
        assert_equal(len(egress_tx["output_chunks"]), 1)
        assert all(output["is_ours"] for output in egress_tx["outputs"])
        assert_equal(egress_tx["output_chunks"][0]["first_output_index"], 0)
        assert_equal(egress_tx["output_chunks"][0]["output_count"], 2)
        assert_equal(egress_tx["output_chunks"][0]["owned_output_count"], 2)
        assert_equal(egress_tx["output_chunks"][0]["owned_amount"], Decimal("0.23"))
        decoded_egress = node.decoderawtransaction(egress_tx["tx_hex"])
        assert_equal(decoded_egress["txid"], egress_tx["txid"])
        assert_equal(decoded_egress["shielded"]["bundle_type"], "v2")
        assert_equal(decoded_egress["shielded"]["family"], "v2_egress_batch")
        assert_equal(len(decoded_egress["shielded"]["payload"]["outputs"]), 2)
        assert_equal(decoded_egress["shielded"]["payload"]["outputs"][0]["note_class"], "user")
        assert_equal(len(decoded_egress["shielded"]["output_chunks"]), 1)
        assert_equal(decoded_egress["shielded"]["output_chunks"][0]["scan_domain"], "opaque")
        assert_greater_than(decoded_egress["shielded"]["proof_payload_bytes"], 0)

        self.log.info("Build-only bridge ingress RPCs return canonical reserve-output previews")
        ingress_mine_addr = ingress_wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, ingress_wallet, ingress_mine_addr, Decimal("1.0"), sync_fun=self.no_op
        )
        ingress_funding_addr = ingress_wallet.z_getnewaddress()
        ingress_shield = ingress_wallet.z_shieldfunds(Decimal("0.40"), ingress_funding_addr)
        assert ingress_shield["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, ingress_mine_addr, sync_fun=self.no_op)

        ingress_intents = [
            {
                "wallet_id": bridge_hex(0xa1),
                "destination_id": bridge_hex(0xa2),
                "amount": Decimal("0.19"),
                "authorization_hash": bridge_hex(0xa3),
                "l2_id": bridge_hex(0xa4),
                "fee": Decimal("0.01"),
            },
        ]
        ingress_reserve_outputs = [
            {"address": ingress_wallet.z_getnewaddress(), "amount": Decimal("0.20")},
        ]
        ingress_statement = build_ingress_statement(
            ingress_wallet,
            ingress_intents,
            bridge_id=bridge_hex(0xa5),
            operation_id=bridge_hex(0xa6),
            domain_id=bridge_hex(0xa7),
            source_epoch=10,
            data_root=bridge_hex(0xa8),
            proof_policy=proof_policy["proof_policy"],
        )
        ingress_proof_receipt = build_proof_receipt(
            ingress_wallet,
            ingress_statement["statement_hex"],
            proof_profile_hex=proof_profile["profile_hex"],
            verifier_key_hash=descriptor["verifier_key_hash"],
            public_values_hash=bridge_hex(0xa9),
            proof_commitment=bridge_hex(0xaa),
        )
        ingress_proof_receipt_policy = {
            "min_receipts": 1,
            "required_proof_system_ids": [descriptor["proof_system_id"]],
            "required_verifier_key_hashes": [descriptor["verifier_key_hash"]],
            "descriptor_proofs": [proof_policy["proofs"][0]["proof_hex"]],
        }
        assert_raises_rpc_error(
            -8,
            "statement commits to proof_policy; options.proof_receipts are required",
            build_ingress_batch_tx,
            ingress_wallet,
            ingress_statement["statement_hex"],
            ingress_intents,
            ingress_reserve_outputs,
        )
        ingress_anchor = build_proof_anchor(
            ingress_wallet,
            ingress_statement["statement_hex"],
            [ingress_proof_receipt["proof_receipt_hex"]],
            ingress_proof_receipt_policy,
        )
        ingress_tx = build_ingress_batch_tx(
            ingress_wallet,
            ingress_statement["statement_hex"],
            ingress_intents,
            ingress_reserve_outputs,
            {
                "proof_receipts": [ingress_proof_receipt["proof_receipt_hex"]],
                "proof_receipt_policy": ingress_proof_receipt_policy,
            },
        )
        assert_equal(ingress_tx["family"], "v2_ingress_batch")
        assert_equal(ingress_tx["statement_hash"], ingress_statement["statement_hash"])
        assert_equal(ingress_tx["external_anchor"], ingress_anchor["external_anchor"])
        assert_equal(ingress_tx["proof_receipt_count"], 1)
        assert_equal(ingress_tx["distinct_proof_receipt_count"], 1)
        assert_equal(len(ingress_tx["intents"]), 1)
        assert_equal(len(ingress_tx["reserve_outputs"]), 1)
        assert_greater_than_or_equal(len(ingress_tx["outputs"]), 1)
        assert_equal(ingress_tx["output_chunks"], [])
        assert "verification_bundle" not in ingress_tx
        assert all(output["is_ours"] for output in ingress_tx["outputs"])
        assert Decimal("0.20") in [output["amount"] for output in ingress_tx["outputs"]]
        decoded_ingress = node.decoderawtransaction(ingress_tx["tx_hex"])
        assert_equal(decoded_ingress["txid"], ingress_tx["txid"])
        assert_equal(decoded_ingress["shielded"]["bundle_type"], "v2")
        assert_equal(decoded_ingress["shielded"]["family"], "v2_ingress_batch")
        assert_equal(len(decoded_ingress["shielded"]["payload"]["ingress_leaves"]), 1)
        assert_greater_than_or_equal(
            len(decoded_ingress["shielded"]["payload"]["reserve_outputs"]),
            len(ingress_tx["reserve_outputs"]),
        )
        for output in decoded_ingress["shielded"]["payload"]["reserve_outputs"]:
            assert_equal(output["note_class"], "reserve")
        assert_greater_than(len(decoded_ingress["shielded"]["payload"]["consumed_nullifiers"]), 0)

        self.log.info("Build-only bridge ingress RPCs derive hybrid settlement anchors when both witness sets are provided")
        hybrid_attestor_addresses = [
            ingress_wallet.getnewaddress(address_type="p2mr"),
            ingress_wallet.getnewaddress(address_type="p2mr"),
        ]
        hybrid_attestors = [export_bridge_key(ingress_wallet, address, "ml-dsa-44") for address in hybrid_attestor_addresses]
        hybrid_verifier_set = build_verifier_set(
            ingress_wallet,
            hybrid_attestors,
            required_signers=2,
            targets=hybrid_attestors,
        )
        hybrid_attestor_proofs = [entry["proof_hex"] for entry in hybrid_verifier_set["proofs"]]
        hybrid_ingress_statement = build_ingress_statement(
            ingress_wallet,
            ingress_intents,
            bridge_id=bridge_hex(0xab),
            operation_id=bridge_hex(0xac),
            domain_id=bridge_hex(0xad),
            source_epoch=12,
            data_root=bridge_hex(0xae),
            verifier_set=hybrid_verifier_set["verifier_set"],
            proof_policy=proof_policy["proof_policy"],
        )
        hybrid_receipt_hexes = [
            sign_batch_receipt(ingress_wallet, hybrid_attestor_addresses[0], hybrid_ingress_statement["statement_hex"])["receipt_hex"],
            sign_batch_receipt(ingress_wallet, hybrid_attestor_addresses[1], hybrid_ingress_statement["statement_hex"])["receipt_hex"],
        ]
        hybrid_proof_receipt = build_proof_receipt(
            ingress_wallet,
            hybrid_ingress_statement["statement_hex"],
            proof_profile_hex=proof_profile["profile_hex"],
            verifier_key_hash=descriptor["verifier_key_hash"],
            public_values_hash=bridge_hex(0xaf),
            proof_commitment=bridge_hex(0xb0),
        )
        hybrid_receipt_policy = {"attestor_proofs": hybrid_attestor_proofs}
        hybrid_proof_receipt_policy = {"descriptor_proofs": [proof_policy["proofs"][0]["proof_hex"]]}
        assert_raises_rpc_error(
            -8,
            "statement commits to verifier_set; options.receipts are required",
            build_ingress_batch_tx,
            ingress_wallet,
            hybrid_ingress_statement["statement_hex"],
            ingress_intents,
            ingress_reserve_outputs,
            {
                "proof_receipts": [hybrid_proof_receipt["proof_receipt_hex"]],
                "proof_receipt_policy": hybrid_proof_receipt_policy,
            },
        )
        assert_raises_rpc_error(
            -8,
            "statement commits to proof_policy; options.proof_receipts are required",
            build_ingress_batch_tx,
            ingress_wallet,
            hybrid_ingress_statement["statement_hex"],
            ingress_intents,
            ingress_reserve_outputs,
            {
                "receipts": hybrid_receipt_hexes,
                "receipt_policy": hybrid_receipt_policy,
            },
        )
        hybrid_anchor = build_hybrid_anchor(
            ingress_wallet,
            hybrid_ingress_statement["statement_hex"],
            hybrid_receipt_hexes,
            [hybrid_proof_receipt["proof_receipt_hex"]],
            {
                "receipt_policy": hybrid_receipt_policy,
                "proof_receipt_policy": hybrid_proof_receipt_policy,
            },
        )
        hybrid_ingress_tx = build_ingress_batch_tx(
            ingress_wallet,
            hybrid_ingress_statement["statement_hex"],
            ingress_intents,
            ingress_reserve_outputs,
            {
                "receipts": hybrid_receipt_hexes,
                "proof_receipts": [hybrid_proof_receipt["proof_receipt_hex"]],
                "receipt_policy": hybrid_receipt_policy,
                "proof_receipt_policy": hybrid_proof_receipt_policy,
            },
        )
        assert_equal(hybrid_ingress_tx["family"], "v2_ingress_batch")
        assert_equal(hybrid_ingress_tx["statement_hash"], hybrid_ingress_statement["statement_hash"])
        assert_equal(hybrid_ingress_tx["external_anchor"], hybrid_anchor["external_anchor"])
        assert_equal(hybrid_ingress_tx["verification_bundle"], hybrid_anchor["verification_bundle"])
        assert_equal(hybrid_ingress_tx["verification_bundle_hash"], hybrid_anchor["verification_bundle_hash"])
        assert_equal(hybrid_ingress_tx["receipt_count"], 2)
        assert_equal(hybrid_ingress_tx["distinct_attestor_count"], 2)
        assert_equal(hybrid_ingress_tx["proof_receipt_count"], 1)
        assert_equal(hybrid_ingress_tx["distinct_proof_receipt_count"], 1)
        assert_equal(len(hybrid_ingress_tx["reserve_outputs"]), 1)
        assert_equal(hybrid_ingress_tx["output_chunks"], [])
        assert all(output["is_ours"] for output in hybrid_ingress_tx["outputs"])
        decoded_hybrid_ingress = node.decoderawtransaction(hybrid_ingress_tx["tx_hex"])
        assert_equal(decoded_hybrid_ingress["txid"], hybrid_ingress_tx["txid"])
        assert_equal(decoded_hybrid_ingress["shielded"]["family"], "v2_ingress_batch")
        assert_greater_than_or_equal(
            len(decoded_hybrid_ingress["shielded"]["payload"]["reserve_outputs"]),
            len(hybrid_ingress_tx["reserve_outputs"]),
        )
        assert_equal(decoded_hybrid_ingress["shielded"]["header"]["proof_envelope"]["settlement_binding_kind"], "native_batch")

        self.log.info("Build-only bridge ingress RPCs support multi-shard reserve-plus-intent batches")
        ingress_multishard_mine_addr = ingress_multishard_wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, ingress_multishard_wallet, ingress_multishard_mine_addr, Decimal("2.0"), sync_fun=self.no_op
        )
        multishard_seed_addr = ingress_multishard_wallet.z_getnewaddress()
        for _ in range(2):
            multishard_seed = ingress_multishard_wallet.z_sendmany(
                [{"address": multishard_seed_addr, "amount": Decimal("0.50")}]
            )
            assert multishard_seed["txid"] in node.getrawmempool()
            self.generatetoaddress(node, 1, ingress_multishard_mine_addr, sync_fun=self.no_op)

        multishard_intents = [
            {
                "wallet_id": bridge_hex(0xb1 + idx),
                "destination_id": bridge_hex(0xc1 + idx),
                "amount": Decimal("0.06"),
                "authorization_hash": bridge_hex(0xd1 + idx),
                "l2_id": bridge_hex(0xe1 + idx),
                "fee": Decimal("0.015"),
            }
            for idx in range(8)
        ]
        multishard_reserve_outputs = [
            {"address": ingress_multishard_wallet.z_getnewaddress(), "amount": Decimal("0.20")}
            for _ in range(2)
        ]
        multishard_statement = build_ingress_statement(
            ingress_multishard_wallet,
            multishard_intents,
            bridge_id=bridge_hex(0xf1),
            operation_id=bridge_hex(0xf2),
            domain_id=bridge_hex(0xf3),
            source_epoch=11,
            data_root=bridge_hex(0xf4),
            proof_policy=proof_policy["proof_policy"],
        )
        multishard_proof_receipt = build_proof_receipt(
            ingress_multishard_wallet,
            multishard_statement["statement_hex"],
            proof_profile_hex=proof_profile["profile_hex"],
            verifier_key_hash=descriptor["verifier_key_hash"],
            public_values_hash=bridge_hex(0xf5),
            proof_commitment=bridge_hex(0xf6),
        )
        multishard_anchor = build_proof_anchor(
            ingress_multishard_wallet,
            multishard_statement["statement_hex"],
            [multishard_proof_receipt["proof_receipt_hex"]],
            ingress_proof_receipt_policy,
        )
        multishard_tx = build_ingress_batch_tx(
            ingress_multishard_wallet,
            multishard_statement["statement_hex"],
            multishard_intents,
            multishard_reserve_outputs,
            {
                "proof_receipts": [multishard_proof_receipt["proof_receipt_hex"]],
                "proof_receipt_policy": ingress_proof_receipt_policy,
            },
        )
        assert_equal(multishard_tx["family"], "v2_ingress_batch")
        assert_equal(multishard_tx["statement_hash"], multishard_statement["statement_hash"])
        assert_equal(multishard_tx["external_anchor"], multishard_anchor["external_anchor"])
        assert_equal(multishard_tx["proof_receipt_count"], 1)
        assert_equal(multishard_tx["distinct_proof_receipt_count"], 1)
        assert_equal(len(multishard_tx["intents"]), 8)
        assert_equal(len(multishard_tx["reserve_outputs"]), 2)
        assert_greater_than_or_equal(len(multishard_tx["outputs"]), 2)
        assert_equal(multishard_tx["output_chunks"], [])
        assert "verification_bundle" not in multishard_tx
        assert all(output["is_ours"] for output in multishard_tx["outputs"])
        reserve_amounts = [output["amount"] for output in multishard_tx["outputs"]]
        assert_equal(reserve_amounts.count(Decimal("0.20")), 2)
        decoded_multishard = node.decoderawtransaction(multishard_tx["tx_hex"])
        assert_equal(decoded_multishard["txid"], multishard_tx["txid"])
        assert_equal(decoded_multishard["shielded"]["family"], "v2_ingress_batch")
        assert_equal(len(decoded_multishard["shielded"]["payload"]["ingress_leaves"]), 8)
        assert_greater_than_or_equal(
            len(decoded_multishard["shielded"]["payload"]["reserve_outputs"]),
            len(multishard_tx["reserve_outputs"]),
        )
        assert_greater_than(len(decoded_multishard["shielded"]["proof_shards"]), 1)


if __name__ == "__main__":
    WalletShieldedRpcSurfaceTest(__file__).main()
