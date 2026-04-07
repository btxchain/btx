// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/bridge_wallet.h>

#include <consensus/validation.h>
#include <crypto/chacha20poly1305.h>
#include <hash.h>
#include <key_io.h>
#include <policy/policy.h>
#include <script/ctv.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <shielded/bundle.h>
#include <streams.h>
#include <util/check.h>
#include <wallet/shielded_privacy.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <type_traits>
#include <utility>

namespace wallet {
namespace {

struct BridgeAuditPayloadV1
{
    uint8_t version{1};
    uint256 note_commitment;
    uint256 recipient_pk_hash;
    CAmount value{0};
    uint256 rho;
    uint256 rcm;

    SERIALIZE_METHODS(BridgeAuditPayloadV1, obj)
    {
        READWRITE(obj.version, obj.note_commitment, obj.recipient_pk_hash, obj.value, obj.rho, obj.rcm);
    }
};

template <typename ByteVector>
class ByteVectorWriter
{
public:
    ByteVectorWriter(ByteVector& data, size_t pos) : m_data{data}, m_pos{pos}
    {
        if (m_pos > m_data.size()) m_data.resize(m_pos);
    }

    void write(Span<const std::byte> src)
    {
        const size_t overwrite = std::min(src.size(), m_data.size() - m_pos);
        if (overwrite > 0) {
            std::memcpy(m_data.data() + m_pos, src.data(), overwrite);
        }
        if (overwrite < src.size()) {
            const size_t append = src.size() - overwrite;
            const size_t old_size = m_data.size();
            m_data.resize(old_size + append);
            std::memcpy(m_data.data() + old_size, src.data() + overwrite, append);
        }
        m_pos += src.size();
    }

    template <typename T>
    ByteVectorWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }

private:
    ByteVector& m_data;
    size_t m_pos;
};

template <typename T>
[[nodiscard]] std::vector<uint8_t, secure_allocator<uint8_t>> SerializeToSecureBytes(const T& obj)
{
    std::vector<uint8_t, secure_allocator<uint8_t>> bytes;
    ByteVectorWriter writer{bytes, 0};
    writer << obj;
    return bytes;
}
[[nodiscard]] bool IsValidPlanKind(shielded::BridgeTemplateKind kind)
{
    return kind == shielded::BridgeTemplateKind::SHIELD || kind == shielded::BridgeTemplateKind::UNSHIELD;
}

[[nodiscard]] bool HasValidCommonFields(const BridgePlan& plan)
{
    return plan.version == 1 &&
           IsValidPlanKind(plan.kind) &&
           plan.ids.IsValid() &&
           shielded::IsValidRefundLockHeight(plan.refund_lock_height) &&
           !plan.ctv_hash.IsNull() &&
           plan.script_tree.IsValid() &&
           plan.script_tree.refund_lock_height == plan.refund_lock_height &&
           plan.script_tree.kind == plan.kind;
}

[[nodiscard]] std::optional<CAmount> SumOutputs(const std::vector<CTxOut>& outputs)
{
    CAmount total{0};
    for (const auto& txout : outputs) {
        if (!MoneyRange(txout.nValue) || txout.nValue <= 0 || txout.scriptPubKey.empty()) return std::nullopt;
        const auto next = CheckedAdd(total, txout.nValue);
        if (!next.has_value() || !MoneyRange(*next)) return std::nullopt;
        total = *next;
    }
    return total;
}

[[nodiscard]] std::optional<uint256> DeriveBridgeHash(const shielded::BridgePlanIds& ids,
                                                      std::string_view domain,
                                                      uint32_t index,
                                                      Span<const unsigned char> extra = {})
{
    if (!ids.IsValid()) return std::nullopt;
    HashWriter hw;
    hw << std::string{"BTX-Bridge-V1"};
    hw << std::string{domain};
    hw << ids.bridge_id;
    hw << ids.operation_id;
    hw << index;
    if (!extra.empty()) {
        hw.write(AsBytes(extra));
    }
    return hw.GetSHA256();
}

[[nodiscard]] std::optional<std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES>> DeriveBridgeSeed32(const shielded::BridgePlanIds& ids,
                                                                                               std::string_view domain,
                                                                                               uint32_t index,
                                                                                               Span<const unsigned char> extra = {})
{
    auto hash = DeriveBridgeHash(ids, domain, index, extra);
    if (!hash.has_value()) return std::nullopt;
    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> out{};
    std::copy(hash->begin(), hash->begin() + mlkem::ENCAPS_SEEDBYTES, out.begin());
    return out;
}

[[nodiscard]] std::optional<std::array<uint8_t, 12>> DeriveBridgeNonce12(const shielded::BridgePlanIds& ids,
                                                                         std::string_view domain,
                                                                         uint32_t index,
                                                                         Span<const unsigned char> extra = {})
{
    auto hash = DeriveBridgeHash(ids, domain, index, extra);
    if (!hash.has_value()) return std::nullopt;
    std::array<uint8_t, 12> out{};
    std::copy(hash->begin(), hash->begin() + out.size(), out.begin());
    return out;
}

[[nodiscard]] bool HasAnyNonZeroBytes(const mlkem::PublicKey& pubkey)
{
    return std::any_of(pubkey.begin(), pubkey.end(), [](uint8_t byte) { return byte != 0; });
}

[[nodiscard]] bool SamePubkey(const mlkem::PublicKey& lhs, const mlkem::PublicKey& rhs)
{
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

[[nodiscard]] bool SameGrantIdentity(const BridgeViewGrantRequest& lhs, const BridgeViewGrantRequest& rhs)
{
    return lhs.format == rhs.format && SamePubkey(lhs.recipient_pubkey, rhs.recipient_pubkey);
}

[[nodiscard]] shielded::viewgrants::StructuredDisclosurePayload BuildStructuredBridgeDisclosurePayload(
    const BridgeInPlanRequest& request,
    const ShieldedNote& note)
{
    shielded::viewgrants::StructuredDisclosurePayload payload;
    payload.amount = note.value;
    payload.recipient_pk_hash = note.recipient_pk_hash;
    payload.memo = note.memo;
    payload.sender.bridge_id = request.ids.bridge_id;
    payload.sender.operation_id = request.ids.operation_id;
    return payload;
}

void MergeBridgeViewGrantRequest(std::vector<BridgeViewGrantRequest>& merged, const BridgeViewGrantRequest& next)
{
    auto it = std::find_if(merged.begin(), merged.end(), [&](const auto& existing) {
        return SameGrantIdentity(existing, next);
    });
    if (it == merged.end()) {
        merged.push_back(next);
        return;
    }

    if (next.format == BridgeViewGrantFormat::STRUCTURED_DISCLOSURE) {
        it->disclosure_flags |= next.disclosure_flags;
    }
}

[[nodiscard]] std::optional<CShieldedBundle> BuildBridgeShieldBundle(const BridgeInPlanRequest& request)
{
    if (!request.ids.IsValid() || !request.operator_key.IsValid() || !request.refund_key.IsValid()) return std::nullopt;
    if (!request.recipient.IsValid() || request.recipient.pk_hash.IsNull() || !request.recipient.HasKEMPublicKey()) return std::nullopt;
    if (!MoneyRange(request.amount) || request.amount <= 0) return std::nullopt;
    if (request.memo.size() > MAX_SHIELDED_MEMO_SIZE) return std::nullopt;
    if (request.shielded_anchor.IsNull()) return std::nullopt;
    if (request.operator_view_grants.size() > MAX_VIEW_GRANTS_PER_TX) return std::nullopt;
    if (request.batch_commitment.has_value()) {
        if (!request.batch_commitment->IsValid()) return std::nullopt;
        if (!request.memo.empty()) return std::nullopt;
        if (request.batch_commitment->direction != shielded::BridgeDirection::BRIDGE_IN) return std::nullopt;
        if (request.batch_commitment->ids.bridge_id != request.ids.bridge_id ||
            request.batch_commitment->ids.operation_id != request.ids.operation_id) {
            return std::nullopt;
        }
        if (request.batch_commitment->total_amount != request.amount) return std::nullopt;
    }

    ShieldedNote note;
    note.value = request.amount;
    note.recipient_pk_hash = request.recipient.pk_hash;
    const auto recipient_kem_pubkey = MakeUCharSpan(request.recipient.kem_pk);
    const auto rho = DeriveBridgeHash(request.ids, "note-rho", 0, recipient_kem_pubkey);
    const auto rcm = DeriveBridgeHash(request.ids, "note-rcm", 0, recipient_kem_pubkey);
    const auto kem_seed = DeriveBridgeSeed32(request.ids, "note-kem-seed", 0, recipient_kem_pubkey);
    const auto nonce = DeriveBridgeNonce12(request.ids, "note-nonce", 0, recipient_kem_pubkey);
    if (!rho.has_value() || !rcm.has_value() || !kem_seed.has_value() || !nonce.has_value()) return std::nullopt;
    note.rho = *rho;
    note.rcm = *rcm;
    if (request.batch_commitment.has_value()) {
        note.memo = shielded::SerializeBridgeBatchCommitment(*request.batch_commitment);
    } else {
        note.memo = request.memo;
    }
    if (!note.IsValid()) return std::nullopt;

    CShieldedOutput output;
    output.note_commitment = note.GetCommitment();
    output.encrypted_note = shielded::NoteEncryption::EncryptDeterministic(note, request.recipient.kem_pk, *kem_seed, *nonce);
    output.range_proof.clear();
    output.merkle_anchor = request.shielded_anchor;

    CShieldedBundle bundle;
    bundle.shielded_outputs.push_back(output);
    bundle.value_balance = -request.amount;

    if (!request.operator_view_grants.empty()) {
        BridgeAuditPayloadV1 payload;
        payload.note_commitment = output.note_commitment;
        payload.recipient_pk_hash = note.recipient_pk_hash;
        payload.value = note.value;
        payload.rho = note.rho;
        payload.rcm = note.rcm;
        const auto legacy_payload = SerializeToSecureBytes(payload);
        auto structured_payload = BuildStructuredBridgeDisclosurePayload(request, note);
        for (size_t i = 0; i < request.operator_view_grants.size(); ++i) {
            const auto& grant_request = request.operator_view_grants[i];
            std::vector<uint8_t, secure_allocator<uint8_t>> payload_bytes;
            if (grant_request.format == BridgeViewGrantFormat::LEGACY_AUDIT) {
                payload_bytes = legacy_payload;
            } else if (grant_request.format == BridgeViewGrantFormat::STRUCTURED_DISCLOSURE) {
                auto grant_payload = structured_payload;
                grant_payload.disclosure_flags = grant_request.disclosure_flags;
                if (!shielded::viewgrants::HasDisclosureField(grant_payload.disclosure_flags,
                                                              shielded::viewgrants::DISCLOSE_AMOUNT)) {
                    grant_payload.amount = 0;
                }
                if (!shielded::viewgrants::HasDisclosureField(grant_payload.disclosure_flags,
                                                              shielded::viewgrants::DISCLOSE_RECIPIENT)) {
                    grant_payload.recipient_pk_hash.SetNull();
                }
                if (!shielded::viewgrants::HasDisclosureField(grant_payload.disclosure_flags,
                                                              shielded::viewgrants::DISCLOSE_MEMO)) {
                    grant_payload.memo.clear();
                }
                if (!shielded::viewgrants::HasDisclosureField(grant_payload.disclosure_flags,
                                                              shielded::viewgrants::DISCLOSE_SENDER)) {
                    grant_payload.sender = {};
                }
                payload_bytes = shielded::viewgrants::SerializeStructuredDisclosurePayloadSecure(grant_payload);
            } else {
                return std::nullopt;
            }

            if (payload_bytes.empty()) return std::nullopt;
            const Span<const unsigned char> payload_span{payload_bytes.data(), payload_bytes.size()};
            if (payload_span.size() >
                MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE - AEADChaCha20Poly1305::EXPANSION) {
                return std::nullopt;
            }
            const auto grant_seed = DeriveBridgeSeed32(request.ids, "view-grant-seed", i, payload_span);
            const auto grant_nonce = DeriveBridgeNonce12(request.ids, "view-grant-nonce", i, payload_span);
            if (!grant_seed.has_value() || !grant_nonce.has_value()) return std::nullopt;
            bundle.view_grants.push_back(CViewGrant::CreateDeterministic(payload_span,
                                                                         grant_request.recipient_pubkey,
                                                                         *grant_seed,
                                                                         *grant_nonce));
        }
    }

    if (!bundle.CheckStructure()) return std::nullopt;
    return bundle;
}

[[nodiscard]] CScript BridgePlanScriptPubKey(const shielded::BridgeScriptTree& tree)
{
    return GetScriptForDestination(WitnessV2P2MR(tree.merkle_root));
}

[[nodiscard]] std::optional<uint256> ComputeBridgeTemplateCTVHash(const CMutableTransaction& mtx)
{
    const CScript dummy_script = GetScriptForDestination(WitnessV2P2MR(uint256{1}));
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, {CTxOut{0, dummy_script}}, /*force=*/true);
    return ComputeCTVHash(mtx, /*nIn=*/0, txdata);
}

[[nodiscard]] std::optional<PartiallySignedTransaction> BuildBridgePlanPsbt(const BridgePlan& plan,
                                                                            const COutPoint& prevout,
                                                                            CAmount prev_value,
                                                                            bool use_refund_path,
                                                                            std::optional<std::vector<unsigned char>> csfs_message = std::nullopt)
{
    if (!HasValidCommonFields(plan) || prevout.IsNull() || !MoneyRange(prev_value) || prev_value <= 0) return std::nullopt;
    if (!use_refund_path && !plan.IsValid()) return std::nullopt;

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = use_refund_path ? plan.refund_lock_height : 0;
    const uint32_t sequence = use_refund_path ? CTxIn::MAX_SEQUENCE_NONFINAL : CTxIn::SEQUENCE_FINAL;
    mtx.vin.emplace_back(prevout, CScript(), sequence);
    mtx.vout = plan.transparent_outputs;
    mtx.shielded_bundle = plan.shielded_bundle;

    if (!use_refund_path) {
        const auto ctv_hash = ComputeBridgeTemplateCTVHash(mtx);
        if (!ctv_hash.has_value() || *ctv_hash != plan.ctv_hash) {
            return std::nullopt;
        }
    }

    PartiallySignedTransaction psbt(mtx);
    auto& input = psbt.inputs[0];
    input.witness_utxo = CTxOut{prev_value, BridgePlanScriptPubKey(plan.script_tree)};
    input.m_p2mr_merkle_root = plan.script_tree.merkle_root;
    if (use_refund_path) {
        input.m_p2mr_leaf_script = plan.script_tree.refund_leaf_script;
        input.m_p2mr_control_block = plan.script_tree.refund_control_block;
    } else {
        input.m_p2mr_leaf_script = plan.script_tree.normal_leaf_script;
        input.m_p2mr_control_block = plan.script_tree.normal_control_block;
        if (csfs_message.has_value()) {
            input.m_p2mr_csfs_msgs.emplace(std::make_pair(plan.script_tree.normal_leaf_hash, plan.script_tree.normal_key.pubkey),
                                           std::move(*csfs_message));
        }
    }
    return psbt;
}

[[nodiscard]] std::optional<CAmount> ComputeBridgeSettlementBaseValue(const BridgePlan& plan)
{
    if (!plan.IsValid()) return std::nullopt;
    if (plan.kind == shielded::BridgeTemplateKind::SHIELD) {
        if (!MoneyRangeSigned(plan.shielded_bundle.value_balance) || plan.shielded_bundle.value_balance >= 0) {
            return std::nullopt;
        }
        return -plan.shielded_bundle.value_balance;
    }
    return SumOutputs(plan.transparent_outputs);
}

[[nodiscard]] bool EnforceCanonicalBridgeSettlementFee(const BridgePlan& plan,
                                                       CAmount prev_value,
                                                       const Consensus::Params* consensus,
                                                       int32_t validation_height)
{
    if (consensus == nullptr ||
        !shielded::UseShieldedCanonicalFeeBuckets(*consensus, validation_height)) {
        return true;
    }

    const auto base_value = ComputeBridgeSettlementBaseValue(plan);
    if (!base_value.has_value() || prev_value < *base_value) {
        return false;
    }

    const CAmount implicit_fee = prev_value - *base_value;
    return MoneyRange(implicit_fee) &&
           shielded::IsCanonicalShieldedFee(implicit_fee, *consensus, validation_height);
}

[[nodiscard]] std::optional<CAmount> CanonicalizeBridgeRefundFee(CAmount fee,
                                                                 CAmount prev_value,
                                                                 const Consensus::Params* consensus,
                                                                 int32_t validation_height)
{
    if (!MoneyRange(fee) || fee < 0 || fee >= prev_value) return std::nullopt;
    if (consensus == nullptr ||
        !shielded::UseShieldedCanonicalFeeBuckets(*consensus, validation_height)) {
        return fee;
    }

    const CAmount rounded_fee =
        shielded::RoundShieldedFeeToCanonicalBucket(fee, *consensus, validation_height);
    if (!MoneyRange(rounded_fee) || rounded_fee < 0 || rounded_fee >= prev_value) {
        return std::nullopt;
    }
    return rounded_fee;
}

} // namespace

bool BridgeViewGrantRequest::IsValid() const
{
    if (!HasAnyNonZeroBytes(recipient_pubkey)) return false;

    switch (format) {
    case BridgeViewGrantFormat::LEGACY_AUDIT:
        return disclosure_flags == 0;
    case BridgeViewGrantFormat::STRUCTURED_DISCLOSURE:
        return shielded::viewgrants::IsValidDisclosureFlags(disclosure_flags);
    }
    return false;
}

bool BridgeDisclosurePolicy::IsValid() const
{
    if (version != 1) return false;
    if (!MoneyRange(threshold_amount) || threshold_amount <= 0) return false;
    if (required_grants.empty() || required_grants.size() > MAX_VIEW_GRANTS_PER_TX) return false;
    return std::all_of(required_grants.begin(), required_grants.end(), [](const auto& grant) { return grant.IsValid(); });
}

bool BridgeDisclosurePolicy::RequiresDisclosure(CAmount amount) const
{
    return IsValid() && amount >= threshold_amount;
}

std::optional<std::string> ValidateAndApplyBridgeDisclosurePolicy(BridgeInPlanRequest& request)
{
    if (request.operator_view_grants.size() > MAX_VIEW_GRANTS_PER_TX) {
        return strprintf("operator_view_grants exceeds %u entries", MAX_VIEW_GRANTS_PER_TX);
    }

    std::vector<BridgeViewGrantRequest> normalized;
    normalized.reserve(request.operator_view_grants.size());
    for (const auto& grant : request.operator_view_grants) {
        if (!grant.IsValid()) return "operator_view_grants contains an invalid entry";
        MergeBridgeViewGrantRequest(normalized, grant);
    }

    if (request.disclosure_policy.has_value()) {
        if (!request.disclosure_policy->IsValid()) return "disclosure_policy is invalid";
        if (request.disclosure_policy->RequiresDisclosure(request.amount)) {
            for (const auto& grant : request.disclosure_policy->required_grants) {
                MergeBridgeViewGrantRequest(normalized, grant);
            }
        }
    }

    if (normalized.size() > MAX_VIEW_GRANTS_PER_TX) {
        return strprintf("resolved operator view grants exceed %u entries", MAX_VIEW_GRANTS_PER_TX);
    }
    request.operator_view_grants = std::move(normalized);
    return std::nullopt;
}

bool BridgePlan::IsValid() const
{
    if (version != 1 || !IsValidPlanKind(kind) || !ids.IsValid()) return false;
    if (!shielded::IsValidRefundLockHeight(refund_lock_height)) return false;
    if (ctv_hash.IsNull() || !script_tree.IsValid()) return false;
    if (script_tree.refund_lock_height != refund_lock_height || script_tree.kind != kind) return false;
    if (kind == shielded::BridgeTemplateKind::SHIELD) {
        if (!transparent_outputs.empty()) return false;
        if (!shielded_bundle.CheckStructure()) return false;
        if (has_attestation) return false;
        return true;
    }
    if (!shielded_bundle.IsEmpty() || transparent_outputs.empty()) return false;
    if (!has_attestation || !shielded::IsWellFormedBridgeAttestation(attestation)) return false;
    const auto outputs_total = SumOutputs(transparent_outputs);
    if (!outputs_total.has_value()) return false;
    return attestation.ids.bridge_id == ids.bridge_id &&
           attestation.ids.operation_id == ids.operation_id &&
           attestation.ctv_hash == ctv_hash &&
           attestation.refund_lock_height == refund_lock_height &&
           attestation.direction == shielded::BridgeDirection::BRIDGE_OUT &&
           (attestation.version == 1 ||
            (attestation.batch_total_amount == *outputs_total && attestation.batch_entry_count > 0));
}

std::optional<BridgePlan> BuildBridgeInPlan(const BridgeInPlanRequest& request)
{
    BridgeInPlanRequest effective_request = request;
    if (auto error = ValidateAndApplyBridgeDisclosurePolicy(effective_request); error.has_value()) {
        return std::nullopt;
    }

    auto bundle = BuildBridgeShieldBundle(effective_request);
    if (!bundle.has_value()) return std::nullopt;

    CMutableTransaction template_tx;
    template_tx.version = CTransaction::CURRENT_VERSION;
    template_tx.nLockTime = 0;
    template_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
    template_tx.shielded_bundle = *bundle;

    auto ctv_hash = ComputeBridgeTemplateCTVHash(template_tx);
    if (!ctv_hash.has_value() || ctv_hash->IsNull()) return std::nullopt;
    auto tree = shielded::BuildShieldBridgeScriptTree(*ctv_hash,
                                                      effective_request.operator_key,
                                                      effective_request.refund_lock_height,
                                                      effective_request.refund_key);
    if (!tree.has_value()) return std::nullopt;

    BridgePlan plan;
    plan.kind = shielded::BridgeTemplateKind::SHIELD;
    plan.ids = effective_request.ids;
    plan.refund_lock_height = effective_request.refund_lock_height;
    plan.ctv_hash = *ctv_hash;
    plan.script_tree = *tree;
    plan.shielded_bundle = *bundle;
    return plan.IsValid() ? std::optional<BridgePlan>{std::move(plan)} : std::nullopt;
}

std::optional<BridgePlan> BuildBridgeOutPlan(const BridgeOutPlanRequest& request)
{
    if (!request.ids.IsValid() || !request.operator_key.IsValid() || !request.refund_key.IsValid()) return std::nullopt;
    if (request.genesis_hash.IsNull()) return std::nullopt;

    std::vector<CTxOut> payouts = request.payouts;
    if (payouts.empty()) {
        payouts.push_back(request.payout);
    }
    const auto outputs_total = SumOutputs(payouts);
    if (!outputs_total.has_value()) return std::nullopt;
    if (request.batch_commitment.has_value()) {
        if (!request.batch_commitment->IsValid()) return std::nullopt;
        if (request.batch_commitment->direction != shielded::BridgeDirection::BRIDGE_OUT) return std::nullopt;
        if (request.batch_commitment->ids.bridge_id != request.ids.bridge_id ||
            request.batch_commitment->ids.operation_id != request.ids.operation_id) {
            return std::nullopt;
        }
        if (request.batch_commitment->total_amount != *outputs_total) return std::nullopt;
    }

    CMutableTransaction template_tx;
    template_tx.version = CTransaction::CURRENT_VERSION;
    template_tx.nLockTime = 0;
    template_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
    template_tx.vout = payouts;

    auto ctv_hash = ComputeBridgeTemplateCTVHash(template_tx);
    if (!ctv_hash.has_value() || ctv_hash->IsNull()) return std::nullopt;
    auto tree = shielded::BuildUnshieldBridgeScriptTree(*ctv_hash,
                                                        request.operator_key,
                                                        request.refund_lock_height,
                                                        request.refund_key);
    if (!tree.has_value()) return std::nullopt;

    BridgePlan plan;
    plan.kind = shielded::BridgeTemplateKind::UNSHIELD;
    plan.ids = request.ids;
    plan.refund_lock_height = request.refund_lock_height;
    plan.ctv_hash = *ctv_hash;
    plan.script_tree = *tree;
    plan.transparent_outputs = std::move(payouts);
    plan.has_attestation = true;
    plan.attestation.version = request.batch_commitment.has_value()
        ? (request.batch_commitment->version >= 2 ? 3 : 2)
        : 1;
    plan.attestation.genesis_hash = request.genesis_hash;
    plan.attestation.direction = shielded::BridgeDirection::BRIDGE_OUT;
    plan.attestation.ids = request.ids;
    plan.attestation.ctv_hash = *ctv_hash;
    plan.attestation.refund_lock_height = request.refund_lock_height;
    if (request.batch_commitment.has_value()) {
        plan.attestation.batch_entry_count = request.batch_commitment->entry_count;
        plan.attestation.batch_total_amount = request.batch_commitment->total_amount;
        plan.attestation.batch_root = request.batch_commitment->batch_root;
        if (request.batch_commitment->version >= 2) {
            plan.attestation.external_anchor = request.batch_commitment->external_anchor;
        }
    }
    return plan.IsValid() ? std::optional<BridgePlan>{std::move(plan)} : std::nullopt;
}

std::optional<PartiallySignedTransaction> CreateBridgeShieldSettlementTransaction(const BridgePlan& plan,
                                                                                  const COutPoint& prevout,
                                                                                  CAmount prev_value,
                                                                                  const Consensus::Params* consensus,
                                                                                  int32_t validation_height)
{
    if (!plan.IsValid() || plan.kind != shielded::BridgeTemplateKind::SHIELD) return std::nullopt;
    if (prev_value < -plan.shielded_bundle.value_balance) return std::nullopt;
    if (!EnforceCanonicalBridgeSettlementFee(plan, prev_value, consensus, validation_height)) {
        return std::nullopt;
    }
    return BuildBridgePlanPsbt(plan, prevout, prev_value, /*use_refund_path=*/false);
}

std::optional<PartiallySignedTransaction> CreateBridgeUnshieldSettlementTransaction(const BridgePlan& plan,
                                                                                    const COutPoint& prevout,
                                                                                    CAmount prev_value,
                                                                                    const Consensus::Params* consensus,
                                                                                    int32_t validation_height)
{
    if (!plan.IsValid() || plan.kind != shielded::BridgeTemplateKind::UNSHIELD) return std::nullopt;
    const auto outputs_total = SumOutputs(plan.transparent_outputs);
    if (!outputs_total.has_value()) return std::nullopt;
    if (prev_value < *outputs_total) return std::nullopt;
    if (!EnforceCanonicalBridgeSettlementFee(plan, prev_value, consensus, validation_height)) {
        return std::nullopt;
    }
    const auto attestation_bytes = shielded::SerializeBridgeAttestationMessage(plan.attestation);
    if (attestation_bytes.empty()) return std::nullopt;
    return BuildBridgePlanPsbt(plan, prevout, prev_value, /*use_refund_path=*/false, attestation_bytes);
}

std::optional<PartiallySignedTransaction> CreateBridgeRefundTransaction(const BridgePlan& plan,
                                                                        const COutPoint& prevout,
                                                                        CAmount prev_value,
                                                                        const CTxDestination& destination,
                                                                        CAmount fee,
                                                                        const Consensus::Params* consensus,
                                                                        int32_t validation_height)
{
    if (!plan.IsValid() || prevout.IsNull() || !IsValidDestination(destination)) return std::nullopt;
    if (!MoneyRange(prev_value) || prev_value <= 0) return std::nullopt;

    const auto effective_fee =
        CanonicalizeBridgeRefundFee(fee, prev_value, consensus, validation_height);
    if (!effective_fee.has_value()) return std::nullopt;

    BridgePlan refund_plan = plan;
    refund_plan.shielded_bundle = CShieldedBundle{};
    refund_plan.transparent_outputs = {CTxOut{prev_value - *effective_fee, GetScriptForDestination(destination)}};
    refund_plan.has_attestation = false;
    return BuildBridgePlanPsbt(refund_plan, prevout, prev_value, /*use_refund_path=*/true);
}

} // namespace wallet
