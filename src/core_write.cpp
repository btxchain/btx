// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>

#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <policy/feerate.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <streams.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <map>
#include <string>
#include <vector>

namespace {

UniValue ShieldedV2EncryptedNotePayloadToUniv(const shielded::v2::EncryptedNotePayload& payload)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("scan_domain", shielded::v2::GetScanDomainName(payload.scan_domain));
    out.pushKV("scan_hint", HexStr(payload.scan_hint));
    out.pushKV("ephemeral_key", payload.ephemeral_key.GetHex());
    out.pushKV("ciphertext_bytes", static_cast<uint64_t>(payload.ciphertext.size()));
    return out;
}

UniValue ShieldedV2OutputDescriptionToUniv(const shielded::v2::OutputDescription& output)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("note_class", shielded::v2::GetNoteClassName(output.note_class));
    out.pushKV("note_commitment", output.note_commitment.GetHex());
    out.pushKV("value_commitment", output.value_commitment.GetHex());
    out.pushKV("encrypted_note", ShieldedV2EncryptedNotePayloadToUniv(output.encrypted_note));
    return out;
}

UniValue ShieldedV2ReserveDeltaToUniv(const shielded::v2::ReserveDelta& delta)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("l2_id", delta.l2_id.GetHex());
    out.pushKV("reserve_delta", ValueFromAmount(delta.reserve_delta));
    return out;
}

UniValue ShieldedV2ProofEnvelopeToUniv(const shielded::v2::ProofEnvelope& envelope)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("proof_kind", shielded::v2::GetProofKindName(envelope.proof_kind));
    out.pushKV("membership_proof_kind",
               shielded::v2::GetProofComponentKindName(envelope.membership_proof_kind));
    out.pushKV("amount_proof_kind",
               shielded::v2::GetProofComponentKindName(envelope.amount_proof_kind));
    out.pushKV("balance_proof_kind",
               shielded::v2::GetProofComponentKindName(envelope.balance_proof_kind));
    out.pushKV("settlement_binding_kind",
               shielded::v2::GetSettlementBindingKindName(envelope.settlement_binding_kind));
    out.pushKV("statement_digest", envelope.statement_digest.GetHex());
    return out;
}

UniValue ShieldedV2BatchLeafToUniv(const shielded::v2::BatchLeaf& leaf)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("family", shielded::v2::GetTransactionFamilyName(leaf.family_id));
    out.pushKV("l2_id", leaf.l2_id.GetHex());
    out.pushKV("destination_commitment", leaf.destination_commitment.GetHex());
    out.pushKV("amount_commitment", leaf.amount_commitment.GetHex());
    out.pushKV("fee_commitment", leaf.fee_commitment.GetHex());
    out.pushKV("position", static_cast<uint64_t>(leaf.position));
    out.pushKV("nonce", leaf.nonce.GetHex());
    out.pushKV("settlement_domain", leaf.settlement_domain.GetHex());
    return out;
}

UniValue ShieldedV2ProofShardDescriptorToUniv(const shielded::v2::ProofShardDescriptor& shard)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("settlement_domain", shard.settlement_domain.GetHex());
    out.pushKV("first_leaf_index", static_cast<uint64_t>(shard.first_leaf_index));
    out.pushKV("leaf_count", static_cast<uint64_t>(shard.leaf_count));
    out.pushKV("leaf_subroot", shard.leaf_subroot.GetHex());
    out.pushKV("nullifier_commitment", shard.nullifier_commitment.GetHex());
    out.pushKV("value_commitment", shard.value_commitment.GetHex());
    out.pushKV("statement_digest", shard.statement_digest.GetHex());
    out.pushKV("proof_metadata", HexStr(shard.proof_metadata));
    out.pushKV("proof_payload_offset", static_cast<uint64_t>(shard.proof_payload_offset));
    out.pushKV("proof_payload_size", static_cast<uint64_t>(shard.proof_payload_size));
    return out;
}

UniValue ShieldedV2OutputChunkDescriptorToUniv(const shielded::v2::OutputChunkDescriptor& chunk)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("scan_domain", shielded::v2::GetScanDomainName(chunk.scan_domain));
    out.pushKV("first_output_index", static_cast<uint64_t>(chunk.first_output_index));
    out.pushKV("output_count", static_cast<uint64_t>(chunk.output_count));
    out.pushKV("ciphertext_bytes", static_cast<uint64_t>(chunk.ciphertext_bytes));
    out.pushKV("scan_hint_commitment", chunk.scan_hint_commitment.GetHex());
    out.pushKV("ciphertext_commitment", chunk.ciphertext_commitment.GetHex());
    return out;
}

UniValue ShieldedV2NettingManifestToUniv(const shielded::v2::NettingManifest& manifest)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("manifest_id", shielded::v2::ComputeNettingManifestId(manifest).GetHex());
    out.pushKV("settlement_window", static_cast<uint64_t>(manifest.settlement_window));
    out.pushKV("aggregate_net_delta", ValueFromAmount(manifest.aggregate_net_delta));
    out.pushKV("gross_flow_commitment", manifest.gross_flow_commitment.GetHex());
    out.pushKV("binding_kind", shielded::v2::GetSettlementBindingKindName(manifest.binding_kind));
    out.pushKV("authorization_digest", manifest.authorization_digest.GetHex());

    UniValue domains(UniValue::VARR);
    for (const auto& entry : manifest.domains) {
        UniValue domain(UniValue::VOBJ);
        domain.pushKV("l2_id", entry.l2_id.GetHex());
        domain.pushKV("net_reserve_delta", ValueFromAmount(entry.net_reserve_delta));
        domains.push_back(std::move(domain));
    }
    out.pushKV("domains", std::move(domains));
    return out;
}

UniValue ShieldedV2TransactionHeaderToUniv(const shielded::v2::TransactionHeader& header)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("family", shielded::v2::GetTransactionFamilyName(header.family_id));
    out.pushKV("proof_envelope", ShieldedV2ProofEnvelopeToUniv(header.proof_envelope));
    out.pushKV("payload_digest", header.payload_digest.GetHex());
    out.pushKV("proof_shard_root", header.proof_shard_root.GetHex());
    out.pushKV("proof_shard_count", static_cast<uint64_t>(header.proof_shard_count));
    out.pushKV("output_chunk_root", header.output_chunk_root.GetHex());
    out.pushKV("output_chunk_count", static_cast<uint64_t>(header.output_chunk_count));
    out.pushKV("netting_manifest_version", static_cast<uint64_t>(header.netting_manifest_version));
    out.pushKV("header_id", shielded::v2::ComputeTransactionHeaderId(header).GetHex());
    return out;
}

UniValue ShieldedV2PayloadToUniv(const shielded::v2::TransactionBundle& bundle)
{
    UniValue out(UniValue::VOBJ);
    switch (shielded::v2::GetBundleSemanticFamily(bundle)) {
    case shielded::v2::TransactionFamily::V2_SEND: {
        const auto& payload = std::get<shielded::v2::SendPayload>(bundle.payload);
        out.pushKV("spend_anchor", payload.spend_anchor.GetHex());
        out.pushKV("fee", ValueFromAmount(payload.fee));

        UniValue spends(UniValue::VARR);
        for (const auto& spend : payload.spends) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("nullifier", spend.nullifier.GetHex());
            entry.pushKV("merkle_anchor", spend.merkle_anchor.GetHex());
            entry.pushKV("account_leaf_commitment", spend.account_leaf_commitment.GetHex());
            if (!spend.note_commitment.IsNull()) {
                entry.pushKV("note_commitment", spend.note_commitment.GetHex());
            } else {
                entry.pushKV("note_commitment_redacted", true);
            }
            entry.pushKV("value_commitment", spend.value_commitment.GetHex());
            spends.push_back(std::move(entry));
        }
        out.pushKV("spends", std::move(spends));

        UniValue outputs(UniValue::VARR);
        for (const auto& output : payload.outputs) {
            outputs.push_back(ShieldedV2OutputDescriptionToUniv(output));
        }
        out.pushKV("outputs", std::move(outputs));
        break;
    }
    case shielded::v2::TransactionFamily::V2_LIFECYCLE: {
        const auto& payload = std::get<shielded::v2::LifecyclePayload>(bundle.payload);
        out.pushKV("transparent_binding_digest", payload.transparent_binding_digest.GetHex());
        UniValue controls(UniValue::VARR);
        for (const auto& control : payload.lifecycle_controls) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("kind", control.kind == shielded::v2::AddressLifecycleControlKind::ROTATE
                                   ? "rotate"
                                   : "revoke");
            entry.pushKV("subject_pk_hash", control.subject.pk_hash.GetHex());
            entry.pushKV("has_successor", control.has_successor);
            if (control.has_successor) {
                entry.pushKV("successor_pk_hash", control.successor.pk_hash.GetHex());
            }
            controls.push_back(std::move(entry));
        }
        out.pushKV("lifecycle_controls", std::move(controls));
        break;
    }
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
        const auto& payload = std::get<shielded::v2::IngressBatchPayload>(bundle.payload);
        out.pushKV("spend_anchor", payload.spend_anchor.GetHex());
        out.pushKV("ingress_root", payload.ingress_root.GetHex());
        out.pushKV("l2_credit_root", payload.l2_credit_root.GetHex());
        out.pushKV("aggregate_reserve_commitment", payload.aggregate_reserve_commitment.GetHex());
        out.pushKV("aggregate_fee_commitment", payload.aggregate_fee_commitment.GetHex());
        out.pushKV("fee", ValueFromAmount(payload.fee));
        out.pushKV("settlement_binding_digest", payload.settlement_binding_digest.GetHex());

        UniValue consumed_spends(UniValue::VARR);
        UniValue nullifiers(UniValue::VARR);
        for (const auto& spend : payload.consumed_spends) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("nullifier", spend.nullifier.GetHex());
            entry.pushKV("account_leaf_commitment", spend.account_leaf_commitment.GetHex());
            consumed_spends.push_back(std::move(entry));
            nullifiers.push_back(spend.nullifier.GetHex());
        }
        out.pushKV("consumed_spends", std::move(consumed_spends));
        out.pushKV("consumed_nullifiers", std::move(nullifiers));

        UniValue leaves(UniValue::VARR);
        for (const auto& leaf : payload.ingress_leaves) {
            leaves.push_back(ShieldedV2BatchLeafToUniv(leaf));
        }
        out.pushKV("ingress_leaves", std::move(leaves));

        UniValue reserve_outputs(UniValue::VARR);
        for (const auto& output : payload.reserve_outputs) {
            reserve_outputs.push_back(ShieldedV2OutputDescriptionToUniv(output));
        }
        out.pushKV("reserve_outputs", std::move(reserve_outputs));
        break;
    }
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
        const auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle.payload);
        out.pushKV("settlement_anchor", payload.settlement_anchor.GetHex());
        out.pushKV("egress_root", payload.egress_root.GetHex());
        out.pushKV("allow_transparent_unwrap", payload.allow_transparent_unwrap);
        out.pushKV("settlement_binding_digest", payload.settlement_binding_digest.GetHex());

        UniValue outputs(UniValue::VARR);
        for (const auto& output : payload.outputs) {
            outputs.push_back(ShieldedV2OutputDescriptionToUniv(output));
        }
        out.pushKV("outputs", std::move(outputs));
        break;
    }
    case shielded::v2::TransactionFamily::V2_REBALANCE: {
        const auto& payload = std::get<shielded::v2::RebalancePayload>(bundle.payload);
        out.pushKV("settlement_binding_digest", payload.settlement_binding_digest.GetHex());
        out.pushKV("batch_statement_digest", payload.batch_statement_digest.GetHex());
        out.pushKV("has_netting_manifest", payload.has_netting_manifest);

        UniValue deltas(UniValue::VARR);
        for (const auto& delta : payload.reserve_deltas) {
            deltas.push_back(ShieldedV2ReserveDeltaToUniv(delta));
        }
        out.pushKV("reserve_deltas", std::move(deltas));

        UniValue reserve_outputs(UniValue::VARR);
        for (const auto& output : payload.reserve_outputs) {
            reserve_outputs.push_back(ShieldedV2OutputDescriptionToUniv(output));
        }
        out.pushKV("reserve_outputs", std::move(reserve_outputs));

        if (payload.has_netting_manifest) {
            out.pushKV("netting_manifest", ShieldedV2NettingManifestToUniv(payload.netting_manifest));
        }
        break;
    }
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR: {
        const auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
        out.pushKV("anchored_netting_manifest_id", payload.anchored_netting_manifest_id.GetHex());

        UniValue claim_ids(UniValue::VARR);
        for (const auto& id : payload.imported_claim_ids) {
            claim_ids.push_back(id.GetHex());
        }
        out.pushKV("imported_claim_ids", std::move(claim_ids));

        UniValue adapter_ids(UniValue::VARR);
        for (const auto& id : payload.imported_adapter_ids) {
            adapter_ids.push_back(id.GetHex());
        }
        out.pushKV("imported_adapter_ids", std::move(adapter_ids));

        UniValue receipt_ids(UniValue::VARR);
        for (const auto& id : payload.proof_receipt_ids) {
            receipt_ids.push_back(id.GetHex());
        }
        out.pushKV("proof_receipt_ids", std::move(receipt_ids));

        UniValue statement_digests(UniValue::VARR);
        for (const auto& digest : payload.batch_statement_digests) {
            statement_digests.push_back(digest.GetHex());
        }
        out.pushKV("batch_statement_digests", std::move(statement_digests));

        UniValue deltas(UniValue::VARR);
        for (const auto& delta : payload.reserve_deltas) {
            deltas.push_back(ShieldedV2ReserveDeltaToUniv(delta));
        }
        out.pushKV("reserve_deltas", std::move(deltas));
        break;
    }
    case shielded::v2::TransactionFamily::V2_GENERIC:
        break;
    }
    return out;
}

UniValue ShieldedBundleToUniv(const CShieldedBundle& bundle)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("bundle_type", bundle.HasV2Bundle() ? "v2" : "legacy");
    out.pushKV("shielded_input_count", static_cast<uint64_t>(bundle.GetShieldedInputCount()));
    out.pushKV("shielded_output_count", static_cast<uint64_t>(bundle.GetShieldedOutputCount()));
    out.pushKV("view_grant_count", static_cast<uint64_t>(bundle.view_grants.size()));
    out.pushKV("value_balance", ValueFromAmount(bundle.value_balance));

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        CHECK_NONFATAL(v2_bundle != nullptr);
        const auto semantic_family = shielded::v2::GetBundleSemanticFamily(*v2_bundle);
        out.pushKV("family", shielded::v2::GetTransactionFamilyName(semantic_family));
        if (semantic_family != v2_bundle->header.family_id) {
            out.pushKV("wire_family", shielded::v2::GetTransactionFamilyName(v2_bundle->header.family_id));
        }
        out.pushKV("bundle_id", shielded::v2::ComputeTransactionBundleId(*v2_bundle).GetHex());
        out.pushKV("header", ShieldedV2TransactionHeaderToUniv(v2_bundle->header));
        out.pushKV("payload", ShieldedV2PayloadToUniv(*v2_bundle));

        UniValue proof_shards(UniValue::VARR);
        for (const auto& shard : v2_bundle->proof_shards) {
            proof_shards.push_back(ShieldedV2ProofShardDescriptorToUniv(shard));
        }
        out.pushKV("proof_shards", std::move(proof_shards));

        UniValue output_chunks(UniValue::VARR);
        for (const auto& chunk : v2_bundle->output_chunks) {
            output_chunks.push_back(ShieldedV2OutputChunkDescriptorToUniv(chunk));
        }
        out.pushKV("output_chunks", std::move(output_chunks));
        out.pushKV("proof_payload_bytes", static_cast<uint64_t>(v2_bundle->proof_payload.size()));
        return out;
    }

    UniValue inputs(UniValue::VARR);
    for (const auto& input : bundle.shielded_inputs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("nullifier", input.nullifier.GetHex());
        UniValue ring_positions(UniValue::VARR);
        for (const auto& position : input.ring_positions) {
            ring_positions.push_back(static_cast<uint64_t>(position));
        }
        entry.pushKV("ring_positions", std::move(ring_positions));
        inputs.push_back(std::move(entry));
    }
    out.pushKV("inputs", std::move(inputs));

    UniValue outputs(UniValue::VARR);
    for (const auto& output : bundle.shielded_outputs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("note_commitment", output.note_commitment.GetHex());
        entry.pushKV("merkle_anchor", output.merkle_anchor.GetHex());
        entry.pushKV("ciphertext_bytes", static_cast<uint64_t>(output.encrypted_note.aead_ciphertext.size()));
        outputs.push_back(std::move(entry));
    }
    out.pushKV("outputs", std::move(outputs));
    out.pushKV("proof_bytes", static_cast<uint64_t>(bundle.proof.size()));
    return out;
}

} // namespace

UniValue ValueFromAmount(const CAmount amount)
{
    static_assert(COIN > 1);
    int64_t quotient = amount / COIN;
    int64_t remainder = amount % COIN;
    if (amount < 0) {
        quotient = -quotient;
        remainder = -remainder;
    }
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", amount < 0 ? "-" : "", quotient, remainder));
}

UniValue ValueFromFeeRate(const CFeeRate& fee_rate)
{
    return UniValue(UniValue::VNUM, fee_rate.SatsToString());
}

std::string FormatScript(const CScript& script)
{
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        std::vector<unsigned char> vch;
        if (script.GetOp(it, op, vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_NOP10) {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_")) {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(std::vector<uint8_t>(it2, it - vch.size())),
                                               HexStr(std::vector<uint8_t>(it - vch.size(), it)));
            } else {
                ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, it)));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, script.end())));
        break;
    }
    return ret.substr(0, ret.empty() ? ret.npos : ret.size() - 1);
}

const std::map<unsigned char, std::string> mapSigHashTypes = {
    {static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL")},
    {static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), std::string("ALL|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE")},
    {static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), std::string("NONE|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE")},
    {static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), std::string("SINGLE|ANYONECANPAY")},
};

std::string SighashToStr(unsigned char sighash_type)
{
    const auto& it = mapSigHashTypes.find(sighash_type);
    if (it == mapSigHashTypes.end()) return "";
    return it->second;
}

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures. For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
std::string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr)) {
                        const unsigned char chSigHashType = vch.back();
                        const auto it = mapSigHashTypes.find(chSigHashType);
                        if (it != mapSigHashTypes.end()) {
                            strSigHashDecode = "[" + it->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

std::string EncodeHexTx(const CTransaction& tx)
{
    DataStream ssTx;
    ssTx << TX_WITH_WITNESS(tx);
    return HexStr(ssTx);
}

void ScriptToUniv(const CScript& script, UniValue& out, bool include_hex, bool include_address, const SigningProvider* provider)
{
    CTxDestination address;

    out.pushKV("asm", ScriptToAsmStr(script));
    if (include_address) {
        out.pushKV("desc", InferDescriptor(script, provider ? *provider : DUMMY_SIGNING_PROVIDER)->ToString());
    }
    if (include_hex) {
        out.pushKV("hex", HexStr(script));
    }

    std::vector<std::vector<unsigned char>> solns;
    const TxoutType type{Solver(script, solns)};

    if (include_address && ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
        out.pushKV("address", EncodeDestination(address));
    }
    out.pushKV("type", GetTxnOutputType(type));
}

void TxToUniv(const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex, const CTxUndo* txundo, TxVerbosity verbosity)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);

    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("hash", tx.GetWitnessHash().GetHex());
    entry.pushKV("version", tx.version);
    entry.pushKV("size", tx.GetTotalSize());
    entry.pushKV("vsize", (GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
    entry.pushKV("weight", GetTransactionWeight(tx));
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin{UniValue::VARR};
    vin.reserve(tx.vin.size());

    // If available, use Undo data to calculate the fee. Note that txundo == nullptr
    // for coinbase transactions and for transactions where undo data is unavailable.
    const bool have_undo = txundo != nullptr;
    CAmount amt_total_in = 0;
    CAmount amt_total_out = 0;

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn& txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase()) {
            in.pushKV("coinbase", HexStr(txin.scriptSig));
        } else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig));
            in.pushKV("scriptSig", std::move(o));
        }
        if (!tx.vin[i].scriptWitness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            txinwitness.reserve(tx.vin[i].scriptWitness.stack.size());
            for (const auto& item : tx.vin[i].scriptWitness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("txinwitness", std::move(txinwitness));
        }
        if (have_undo) {
            const Coin& prev_coin = txundo->vprevout[i];
            const CTxOut& prev_txout = prev_coin.out;

            amt_total_in += prev_txout.nValue;

            if (verbosity == TxVerbosity::SHOW_DETAILS_AND_PREVOUT) {
                UniValue o_script_pub_key(UniValue::VOBJ);
                ScriptToUniv(prev_txout.scriptPubKey, /*out=*/o_script_pub_key, /*include_hex=*/true, /*include_address=*/true);

                UniValue p(UniValue::VOBJ);
                p.pushKV("generated", bool(prev_coin.fCoinBase));
                p.pushKV("height", uint64_t(prev_coin.nHeight));
                p.pushKV("value", ValueFromAmount(prev_txout.nValue));
                p.pushKV("scriptPubKey", std::move(o_script_pub_key));
                in.pushKV("prevout", std::move(p));
            }
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(std::move(in));
    }
    entry.pushKV("vin", std::move(vin));

    UniValue vout(UniValue::VARR);
    vout.reserve(tx.vout.size());
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        out.pushKV("value", ValueFromAmount(txout.nValue));
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
        out.pushKV("scriptPubKey", std::move(o));
        vout.push_back(std::move(out));

        if (have_undo) {
            amt_total_out += txout.nValue;
        }
    }
    entry.pushKV("vout", std::move(vout));

    if (have_undo) {
        const CAmount fee = amt_total_in - amt_total_out;
        CHECK_NONFATAL(MoneyRange(fee));
        entry.pushKV("fee", ValueFromAmount(fee));
    }

    if (!block_hash.IsNull()) {
        entry.pushKV("blockhash", block_hash.GetHex());
    }

    if (tx.HasShieldedBundle()) {
        entry.pushKV("shielded", ShieldedBundleToUniv(tx.GetShieldedBundle()));
    }

    if (include_hex) {
        entry.pushKV("hex", EncodeHexTx(tx)); // The hex-encoded transaction. Used the name "hex" to be consistent with the verbose output of "getrawtransaction".
    }
}
