#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import json
from decimal import Decimal
from pathlib import Path
import subprocess

from test_framework.shielded_utils import encrypt_and_unlock_wallet, fund_trusted_transparent_balance
from test_framework.util import assert_equal


def bridge_hex(value):
    return f"{value:064x}"


def get_pq_pubkey(wallet):
    address = wallet.getnewaddress(address_type="p2mr")
    return wallet.exportpqkey(address)["pubkey"]


def export_bridge_key(wallet, address, algorithm="ml-dsa-44"):
    exported = wallet.exportpqkey(address, algorithm)
    return {"algo": exported["algorithm"], "pubkey": exported["pubkey"]}


def get_kem_public_key(wallet):
    zaddr = wallet.z_getnewaddress()
    validated = wallet.z_validateaddress(zaddr)
    kem_public_key = validated.get("kem_public_key")
    if kem_public_key is not None:
        return zaddr, kem_public_key

    exported = wallet.z_exportviewingkey(zaddr, True)
    return zaddr, exported["kem_public_key"]


def create_bridge_wallet(test, node, wallet_name="bridge", amount=Decimal("6")):
    node.createwallet(wallet_name=wallet_name, descriptors=True)
    wallet = encrypt_and_unlock_wallet(node, wallet_name)
    mine_addr = wallet.getnewaddress(address_type="p2mr")
    fund_trusted_transparent_balance(
        test,
        node,
        wallet,
        mine_addr,
        amount,
        maturity_blocks=101,
        sync_fun=test.no_op,
    )
    return wallet, mine_addr


def find_output(node, txid, address, wallet):
    tx = node.decoderawtransaction(wallet.gettransaction(txid)["hex"])
    for vout in tx["vout"]:
        script = vout["scriptPubKey"]
        if script.get("address") == address:
            return int(vout["n"]), Decimal(str(vout["value"]))
    raise AssertionError(f"output for {address} not found in {txid}")


def sign_finalize_and_send(wallet, node, psbt):
    processed = wallet.walletprocesspsbt(psbt)
    if processed["complete"]:
        tx_hex = processed["hex"]
    else:
        finalized = wallet.finalizepsbt(processed["psbt"])
        assert_equal(finalized["complete"], True)
        tx_hex = finalized["hex"]
    txid = node.sendrawtransaction(tx_hex)
    return txid, tx_hex


def mine_block(test, node, mine_addr, blocks=1):
    test.generatetoaddress(node, blocks, mine_addr, sync_fun=test.no_op)


def _shielded_relay_fixture_binary(test):
    return (
        Path(test.config["environment"]["BUILDDIR"])
        / "bin"
        / f"gen_shielded_relay_fixture_tx{test.config['environment']['EXEEXT']}"
    )


def _spend_path_recovery_fixture_binary(test):
    return (
        Path(test.config["environment"]["BUILDDIR"])
        / "bin"
        / f"gen_shielded_spend_path_recovery_fixture{test.config['environment']['EXEEXT']}"
    )


def build_signed_shielded_relay_fixture_tx(
    test,
    node,
    wallet,
    family,
    utxo,
    *,
    fee_sats=40_000,
    require_mempool_accept=False,
):
    change_addr = wallet.getnewaddress(address_type="p2mr")
    change_script = wallet.getaddressinfo(change_addr)["scriptPubKey"]
    fixture = json.loads(
        subprocess.check_output(
            [
                str(_shielded_relay_fixture_binary(test)),
                f"--family={family}",
                f"--input-txid={utxo['txid']}",
                f"--input-vout={utxo['vout']}",
                f"--input-value-sats={int(Decimal(str(utxo['amount'])) * 100_000_000)}",
                f"--change-script={change_script}",
                f"--fee-sats={fee_sats}",
            ],
            text=True,
        )
    )
    signed = wallet.signrawtransactionwithwallet(fixture["tx_hex"])
    assert signed["complete"], signed
    fixture["signed_tx_hex"] = signed["hex"]
    fixture["txid"] = node.decoderawtransaction(signed["hex"])["txid"]
    if require_mempool_accept:
        accept = node.testmempoolaccept(rawtxs=[fixture["signed_tx_hex"]], maxfeerate=0)[0]
        assert_equal(accept["allowed"], True)
    return fixture


def build_unsigned_shielded_relay_fixture_tx(test, node, family, *, require_mempool_accept=False):
    fixture = json.loads(
        subprocess.check_output(
            [
                str(_shielded_relay_fixture_binary(test)),
                f"--family={family}",
            ],
            text=True,
        )
    )
    fixture["txid"] = node.decoderawtransaction(fixture["tx_hex"])["txid"]
    if require_mempool_accept:
        accept = node.testmempoolaccept(rawtxs=[fixture["tx_hex"]], maxfeerate=0)[0]
        assert_equal(accept["allowed"], True)
    return fixture


def build_spend_path_recovery_fixture(
    test,
    funding_utxos,
    *,
    validation_height,
    matrict_disable_height,
    legacy_fee_sats=1_000,
    recovery_fee_sats=1_000,
):
    args = [
        str(_spend_path_recovery_fixture_binary(test)),
        f"--validation-height={validation_height}",
        f"--matrict-disable-height={matrict_disable_height}",
        f"--legacy-fee-sats={legacy_fee_sats}",
        f"--recovery-fee-sats={recovery_fee_sats}",
    ]
    for utxo in funding_utxos:
        args.append(
            "--legacy-input="
            f"{utxo['txid']}:{utxo['vout']}:"
            f"{int(Decimal(str(utxo['amount'])) * 100_000_000)}"
        )
    return json.loads(subprocess.check_output(args, text=True))


def planin(wallet, amount, refund_lock_height, *, bridge_id, operation_id, recipient=None,
           shielded_anchor=None, memo=None, memo_hex=None, operator_view_pubkeys=None,
           operator_view_grants=None, disclosure_policy=None, operator_key=None, refund_key=None):
    if operator_key is None:
        operator_key = get_pq_pubkey(wallet)
    if refund_key is None:
        refund_key = get_pq_pubkey(wallet)
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "refund_lock_height": refund_lock_height,
    }
    if recipient is not None:
        options["recipient"] = recipient
    if shielded_anchor is not None:
        options["shielded_anchor"] = shielded_anchor
    if memo is not None:
        options["memo"] = memo
    if memo_hex is not None:
        options["memo_hex"] = memo_hex
    if operator_view_pubkeys is not None:
        options["operator_view_pubkeys"] = operator_view_pubkeys
    if operator_view_grants is not None:
        options["operator_view_grants"] = operator_view_grants
    if disclosure_policy is not None:
        options["disclosure_policy"] = disclosure_policy
    return wallet.bridge_planin(operator_key, refund_key, amount, options), operator_key, refund_key


def planbatchin(wallet, leaves, refund_lock_height, *, bridge_id, operation_id, recipient=None,
                shielded_anchor=None, operator_view_pubkeys=None, operator_view_grants=None,
                disclosure_policy=None, external_anchor=None, operator_key=None, refund_key=None):
    if operator_key is None:
        operator_key = get_pq_pubkey(wallet)
    if refund_key is None:
        refund_key = get_pq_pubkey(wallet)
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "refund_lock_height": refund_lock_height,
    }
    if recipient is not None:
        options["recipient"] = recipient
    if shielded_anchor is not None:
        options["shielded_anchor"] = shielded_anchor
    if external_anchor is not None:
        options["external_anchor"] = external_anchor
    if operator_view_pubkeys is not None:
        options["operator_view_pubkeys"] = operator_view_pubkeys
    if operator_view_grants is not None:
        options["operator_view_grants"] = operator_view_grants
    if disclosure_policy is not None:
        options["disclosure_policy"] = disclosure_policy
    return wallet.bridge_planbatchin(operator_key, refund_key, leaves, options), operator_key, refund_key


def planout(wallet, payout_address, amount, refund_lock_height, *, bridge_id, operation_id,
            genesis_hash=None, operator_key=None, refund_key=None):
    if operator_key is None:
        operator_key = get_pq_pubkey(wallet)
    if refund_key is None:
        refund_key = get_pq_pubkey(wallet)
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "refund_lock_height": refund_lock_height,
    }
    if genesis_hash is not None:
        options["genesis_hash"] = genesis_hash
    return wallet.bridge_planout(operator_key, refund_key, payout_address, amount, options), operator_key, refund_key


def planbatchout(wallet, payouts, refund_lock_height, *, bridge_id, operation_id,
                 genesis_hash=None, operator_key=None, refund_key=None, batch_commitment_hex=None):
    if operator_key is None:
        operator_key = get_pq_pubkey(wallet)
    if refund_key is None:
        refund_key = get_pq_pubkey(wallet)
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "refund_lock_height": refund_lock_height,
    }
    if genesis_hash is not None:
        options["genesis_hash"] = genesis_hash
    if batch_commitment_hex is not None:
        options["batch_commitment_hex"] = batch_commitment_hex
    return wallet.bridge_planbatchout(operator_key, refund_key, payouts, options), operator_key, refund_key


def sign_batch_authorization(wallet, authorizer_address, direction, authorization, *,
                             bridge_id, operation_id, algorithm="ml-dsa-44"):
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "algorithm": algorithm,
    }
    return wallet.bridge_signbatchauthorization(authorizer_address, direction, authorization, options)


def build_verifier_set(wallet, attestors, *, required_signers, targets=None):
    options = {"required_signers": required_signers}
    if targets is not None:
        options["targets"] = targets
    return wallet.bridge_buildverifierset(attestors, options)


def build_proof_policy(wallet, descriptors, *, required_receipts, targets=None):
    options = {"required_receipts": required_receipts}
    if targets is not None:
        options["targets"] = targets
    return wallet.bridge_buildproofpolicy(descriptors, options)


def build_batch_statement(wallet, direction, entries, *, bridge_id, operation_id, domain_id, source_epoch, data_root,
                          verifier_set=None, proof_policy=None):
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "external_statement": {
            "domain_id": domain_id,
            "source_epoch": source_epoch,
            "data_root": data_root,
        },
    }
    if verifier_set is not None:
        options["external_statement"]["verifier_set"] = verifier_set
    if proof_policy is not None:
        options["external_statement"]["proof_policy"] = proof_policy
    return wallet.bridge_buildbatchstatement(direction, entries, options)


def build_egress_statement(wallet, recipients, *, bridge_id, operation_id, domain_id, source_epoch, data_root,
                           verifier_set=None, proof_policy=None):
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "external_statement": {
            "domain_id": domain_id,
            "source_epoch": source_epoch,
            "data_root": data_root,
        },
    }
    if verifier_set is not None:
        options["external_statement"]["verifier_set"] = verifier_set
    if proof_policy is not None:
        options["external_statement"]["proof_policy"] = proof_policy
    return wallet.bridge_buildegressstatement(recipients, options)


def build_ingress_statement(wallet, intents, *, bridge_id, operation_id, domain_id, source_epoch, data_root,
                            verifier_set=None, proof_policy=None):
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
        "external_statement": {
            "domain_id": domain_id,
            "source_epoch": source_epoch,
            "data_root": data_root,
        },
    }
    if verifier_set is not None:
        options["external_statement"]["verifier_set"] = verifier_set
    if proof_policy is not None:
        options["external_statement"]["proof_policy"] = proof_policy
    return wallet.bridge_buildingressstatement(intents, options)


def sign_batch_receipt(wallet, attestor_address, statement_hex, *, algorithm="ml-dsa-44"):
    return wallet.bridge_signbatchreceipt(attestor_address, statement_hex, {"algorithm": algorithm})


def build_proof_profile(wallet, *, family, proof_type, claim_system):
    return wallet.bridge_buildproofprofile(
        {
            "family": family,
            "proof_type": proof_type,
            "claim_system": claim_system,
        }
    )


def build_proof_claim(wallet, statement_hex, *, kind):
    return wallet.bridge_buildproofclaim(statement_hex, {"kind": kind})


def list_proof_adapters(wallet):
    return wallet.bridge_listproofadapters()


def list_prover_templates(wallet):
    return wallet.bridge_listprovertemplates()


def build_proof_adapter(wallet, *, adapter_name=None, proof_profile_hex=None, proof_profile=None, claim_kind=None):
    adapter = {}
    if adapter_name is not None:
        adapter["adapter_name"] = adapter_name
    if proof_profile_hex is not None:
        adapter["proof_profile_hex"] = proof_profile_hex
    if proof_profile is not None:
        adapter["proof_profile"] = proof_profile
    if claim_kind is not None:
        adapter["claim_kind"] = claim_kind
    return wallet.bridge_buildproofadapter(adapter)


def build_proof_artifact(wallet, statement_hex, *, verifier_key_hash, proof_commitment,
                         proof_size_bytes, public_values_size_bytes, auxiliary_data_size_bytes=None,
                         artifact_commitment=None, artifact_hex=None,
                         proof_adapter_name=None, proof_adapter_hex=None, proof_adapter=None):
    artifact = {
        "verifier_key_hash": verifier_key_hash,
        "proof_commitment": proof_commitment,
        "proof_size_bytes": proof_size_bytes,
        "public_values_size_bytes": public_values_size_bytes,
    }
    if auxiliary_data_size_bytes is not None:
        artifact["auxiliary_data_size_bytes"] = auxiliary_data_size_bytes
    if artifact_commitment is not None:
        artifact["artifact_commitment"] = artifact_commitment
    if artifact_hex is not None:
        artifact["artifact_hex"] = artifact_hex
    if proof_adapter_name is not None:
        artifact["proof_adapter_name"] = proof_adapter_name
    if proof_adapter_hex is not None:
        artifact["proof_adapter_hex"] = proof_adapter_hex
    if proof_adapter is not None:
        artifact["proof_adapter"] = proof_adapter
    return wallet.bridge_buildproofartifact(statement_hex, artifact)


def build_data_artifact(wallet, statement_hex, *, kind, payload_size_bytes,
                        payload_commitment=None, payload_hex=None,
                        artifact_commitment=None, artifact_hex=None,
                        auxiliary_data_size_bytes=None):
    artifact = {
        "kind": kind,
        "payload_size_bytes": payload_size_bytes,
    }
    if payload_commitment is not None:
        artifact["payload_commitment"] = payload_commitment
    if payload_hex is not None:
        artifact["payload_hex"] = payload_hex
    if artifact_commitment is not None:
        artifact["artifact_commitment"] = artifact_commitment
    if artifact_hex is not None:
        artifact["artifact_hex"] = artifact_hex
    if auxiliary_data_size_bytes is not None:
        artifact["auxiliary_data_size_bytes"] = auxiliary_data_size_bytes
    return wallet.bridge_builddataartifact(statement_hex, artifact)


def build_aggregate_artifact_bundle(wallet, statement_hex, *, proof_artifacts=None, data_artifacts=None):
    bundle = {}
    if proof_artifacts is not None:
        bundle["proof_artifacts"] = proof_artifacts
    if data_artifacts is not None:
        bundle["data_artifacts"] = data_artifacts
    return wallet.bridge_buildaggregateartifactbundle(statement_hex, bundle)


def build_aggregate_settlement(wallet, statement_hex, aggregate):
    return wallet.bridge_buildaggregatesettlement(statement_hex, aggregate)


def build_proof_compression_target(wallet, aggregate_settlement_hex, options):
    return wallet.bridge_buildproofcompressiontarget(aggregate_settlement_hex, options)


def build_shielded_state_profile(wallet, state_profile=None):
    if state_profile is None:
        return wallet.bridge_buildshieldedstateprofile()
    return wallet.bridge_buildshieldedstateprofile(state_profile)


def build_state_retention_policy(wallet, retention_policy=None):
    if retention_policy is None:
        return wallet.bridge_buildstateretentionpolicy()
    return wallet.bridge_buildstateretentionpolicy(retention_policy)


def build_prover_sample(wallet, *, proof_artifact_hex=None, proof_artifact=None,
                        prover_template_name=None,
                        native_millis=None, cpu_millis=None, gpu_millis=None, network_millis=None,
                        peak_memory_bytes=None):
    sample = {}
    if proof_artifact_hex is not None:
        sample["proof_artifact_hex"] = proof_artifact_hex
    if proof_artifact is not None:
        sample["proof_artifact"] = proof_artifact
    if prover_template_name is not None:
        sample["prover_template_name"] = prover_template_name
    if native_millis is not None:
        sample["native_millis"] = native_millis
    if cpu_millis is not None:
        sample["cpu_millis"] = cpu_millis
    if gpu_millis is not None:
        sample["gpu_millis"] = gpu_millis
    if network_millis is not None:
        sample["network_millis"] = network_millis
    if peak_memory_bytes is not None:
        sample["peak_memory_bytes"] = peak_memory_bytes
    return wallet.bridge_buildproversample(sample)


def build_prover_profile(wallet, samples):
    return wallet.bridge_buildproverprofile(samples)


def build_prover_benchmark(wallet, profiles):
    return wallet.bridge_buildproverbenchmark(profiles)


def build_proof_receipt(wallet, statement_hex, *, verifier_key_hash=None, proof_commitment=None,
                        public_values_hash=None, claim_hex=None, claim=None,
                        proof_artifact_hex=None, proof_artifact=None,
                        proof_adapter_name=None, proof_adapter_hex=None, proof_adapter=None,
                        proof_system_id=None, proof_profile_hex=None, proof_profile=None):
    receipt = {}
    if verifier_key_hash is not None:
        receipt["verifier_key_hash"] = verifier_key_hash
    if proof_commitment is not None:
        receipt["proof_commitment"] = proof_commitment
    if public_values_hash is not None:
        receipt["public_values_hash"] = public_values_hash
    if claim_hex is not None:
        receipt["claim_hex"] = claim_hex
    if claim is not None:
        receipt["claim"] = claim
    if proof_artifact_hex is not None:
        receipt["proof_artifact_hex"] = proof_artifact_hex
    if proof_artifact is not None:
        receipt["proof_artifact"] = proof_artifact
    if proof_adapter_name is not None:
        receipt["proof_adapter_name"] = proof_adapter_name
    if proof_adapter_hex is not None:
        receipt["proof_adapter_hex"] = proof_adapter_hex
    if proof_adapter is not None:
        receipt["proof_adapter"] = proof_adapter
    if proof_system_id is not None:
        receipt["proof_system_id"] = proof_system_id
    if proof_profile_hex is not None:
        receipt["proof_profile_hex"] = proof_profile_hex
    if proof_profile is not None:
        receipt["proof_profile"] = proof_profile
    return wallet.bridge_buildproofreceipt(statement_hex, receipt)


def build_egress_batch_tx(wallet, statement_hex, descriptors, proof_receipt_hexes, recipients, *,
                          imported_descriptor_index=0, imported_receipt_index=0, output_chunk_sizes=None):
    options = {
        "imported_descriptor_index": imported_descriptor_index,
        "imported_receipt_index": imported_receipt_index,
    }
    if output_chunk_sizes is not None:
        options["output_chunk_sizes"] = output_chunk_sizes
    return wallet.bridge_buildegressbatchtx(statement_hex, descriptors, proof_receipt_hexes, recipients, options)


def build_ingress_batch_tx(wallet, statement_hex, intents, reserve_outputs, options=None):
    if options is None:
        options = {}
    return wallet.bridge_buildingressbatchtx(statement_hex, intents, reserve_outputs, options)


def build_proof_anchor(wallet, statement_hex, proof_receipt_hexes, options=None):
    if options is None:
        options = {}
    return wallet.bridge_buildproofanchor(statement_hex, proof_receipt_hexes, options)


def build_hybrid_anchor(wallet, statement_hex, receipt_hexes, proof_receipt_hexes, options=None):
    if options is None:
        options = {}
    return wallet.bridge_buildhybridanchor(statement_hex, receipt_hexes, proof_receipt_hexes, options)


def build_external_anchor(wallet, statement_hex, receipt_hexes, options=None):
    if options is None:
        options = {}
    return wallet.bridge_buildexternalanchor(statement_hex, receipt_hexes, options)


def build_batch_commitment(wallet, direction, entries, *, bridge_id, operation_id, external_anchor=None):
    options = {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
    }
    if external_anchor is not None:
        options["external_anchor"] = external_anchor
    return wallet.bridge_buildbatchcommitment(direction, entries, options)


def estimate_capacity(wallet, footprint, options=None):
    if options is None:
        return wallet.bridge_estimatecapacity(footprint)
    return wallet.bridge_estimatecapacity(footprint, options)


def estimate_state_growth(wallet, aggregate_settlement_hex, options=None):
    if options is None:
        return wallet.bridge_estimatestategrowth(aggregate_settlement_hex)
    return wallet.bridge_estimatestategrowth(aggregate_settlement_hex, options)


def estimate_state_retention(wallet, aggregate_settlement_hex, options=None):
    if options is None:
        return wallet.bridge_estimatestateretention(aggregate_settlement_hex)
    return wallet.bridge_estimatestateretention(aggregate_settlement_hex, options)
