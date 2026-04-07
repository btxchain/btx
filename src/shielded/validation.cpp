// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/validation.h>

#include <chainparams.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <shielded/lattice/params.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_proof.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace shielded::ringct;

[[nodiscard]] std::string MapSpendAuthReject(const std::string& generic_reject)
{
    if (generic_reject == "bad-shielded-proof-missing") return "bad-shielded-spend-auth-proof-missing";
    if (generic_reject == "bad-shielded-proof-oversize") return "bad-shielded-spend-auth-proof-oversize";
    if (generic_reject == "bad-shielded-proof-encoding") return "bad-shielded-spend-auth-proof-encoding";
    if (generic_reject == "bad-smile2-proof-rice-codec") return "bad-shielded-spend-auth-proof-rice-codec";
    if (generic_reject == "bad-smile2-proof-noncanonical-codec") {
        return "bad-shielded-spend-auth-proof-noncanonical-codec";
    }
    return "bad-shielded-spend-auth-proof";
}

[[nodiscard]] bool RejectRetiredMatRiCTEnvelopeAfterDisable(const CShieldedBundle& bundle,
                                                            const Consensus::Params& consensus,
                                                            int32_t validation_height,
                                                            std::string& reject_reason)
{
    if (!bundle.HasV2Bundle() || !consensus.IsShieldedMatRiCTDisabled(validation_height)) {
        return true;
    }

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr) {
        reject_reason = "bad-shielded-v2-contextual";
        return false;
    }

    const auto& envelope = v2_bundle->header.proof_envelope;
    if (envelope.proof_kind == shielded::v2::ProofKind::DIRECT_MATRICT ||
        envelope.proof_kind == shielded::v2::ProofKind::BATCH_MATRICT ||
        envelope.membership_proof_kind == shielded::v2::ProofComponentKind::MATRICT ||
        envelope.amount_proof_kind == shielded::v2::ProofComponentKind::RANGE ||
        envelope.balance_proof_kind == shielded::v2::ProofComponentKind::BALANCE) {
        reject_reason = "bad-shielded-matrict-disabled";
        return false;
    }
    return true;
}

[[nodiscard]] bool RejectShieldedCanonicalFeeBucket(const shielded::v2::TransactionFamily family_id,
                                                    CAmount fee,
                                                    const Consensus::Params* consensus,
                                                    int32_t validation_height,
                                                    std::string& reject_reason)
{
    if (consensus == nullptr ||
        !shielded::UseShieldedCanonicalFeeBuckets(*consensus, validation_height) ||
        shielded::IsCanonicalShieldedFee(fee, *consensus, validation_height)) {
        return true;
    }

    switch (family_id) {
    case shielded::v2::TransactionFamily::V2_SEND:
        reject_reason = "bad-shielded-v2-send-fee-bucket";
        return false;
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        reject_reason = "bad-shielded-v2-lifecycle-fee-bucket";
        return false;
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
        reject_reason = "bad-shielded-v2-ingress-fee-bucket";
        return false;
    default:
        return true;
    }
}

[[nodiscard]] bool RejectShieldedMinimumPrivacyPool(size_t ring_size,
                                                    uint64_t tree_size,
                                                    const Consensus::Params* consensus,
                                                    int32_t validation_height,
                                                    std::string& reject_reason)
{
    if (consensus == nullptr || !consensus->IsShieldedMatRiCTDisabled(validation_height)) {
        return true;
    }

    const uint64_t minimum_tree_size = shielded::ringct::GetMinimumPrivacyTreeSize(ring_size);
    if (minimum_tree_size > 0 && tree_size < minimum_tree_size) {
        reject_reason = "bad-shielded-anonymity-pool-size";
        return false;
    }
    return true;
}

[[nodiscard]] bool RejectPostForkDirectSendPublicFlow(const shielded::v2::SendPayload& payload,
                                                      const CTransaction& tx,
                                                      const Consensus::Params* consensus,
                                                      int32_t validation_height,
                                                      std::string& reject_reason)
{
    if (consensus == nullptr || !consensus->IsShieldedMatRiCTDisabled(validation_height)) {
        return true;
    }

    if (!payload.spends.empty()) {
        return true;
    }

    if (!payload.lifecycle_controls.empty()) {
        reject_reason = "bad-shielded-v2-send-lifecycle-control";
        return false;
    }

    if (!tx.vout.empty()) {
        reject_reason = "bad-shielded-v2-send-public-flow-disabled";
        return false;
    }

    if (!tx.vin.empty()) {
        return true;
    }

    if (payload.value_balance != payload.fee) {
        reject_reason = "bad-shielded-v2-send-public-flow-disabled";
        return false;
    }
    return true;
}

[[nodiscard]] bool RejectDirectSendEncodingForFork(const shielded::v2::SendPayload& payload,
                                                   const Consensus::Params* consensus,
                                                   int32_t validation_height,
                                                   std::string& reject_reason)
{
    if (consensus == nullptr) {
        return true;
    }

    const bool postfork = consensus->IsShieldedMatRiCTDisabled(validation_height);
    if (postfork) {
        if (!payload.spends.empty() &&
            payload.output_encoding != shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK) {
            reject_reason = "bad-shielded-v2-send-encoding";
            return false;
        }
        if (!payload.lifecycle_controls.empty()) {
            reject_reason = "bad-shielded-v2-send-lifecycle-control";
            return false;
        }
        return true;
    }

    if (payload.output_encoding == shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK) {
        reject_reason = "bad-shielded-v2-send-encoding";
        return false;
    }
    return true;
}

[[nodiscard]] bool RejectMismatchedV2WireFamilyForFork(const shielded::v2::TransactionBundle& bundle,
                                                       const Consensus::Params* consensus,
                                                       int32_t validation_height,
                                                       std::string& reject_reason)
{
    if (consensus == nullptr) {
        return true;
    }

    const bool expects_generic_wire_family =
        shielded::v2::UseGenericV2WireFamily(consensus, validation_height);
    const bool uses_generic_wire_family =
        shielded::v2::IsGenericTransactionFamily(bundle.header.family_id);
    if (expects_generic_wire_family != uses_generic_wire_family) {
        reject_reason = "bad-shielded-v2-family-wire";
        return false;
    }
    return true;
}

[[nodiscard]] bool RejectMismatchedV2ProofEnvelopeForFork(const shielded::v2::TransactionBundle& bundle,
                                                          shielded::v2::TransactionFamily semantic_family,
                                                          const Consensus::Params* consensus,
                                                          int32_t validation_height,
                                                          std::string& reject_reason)
{
    if (consensus == nullptr) {
        return true;
    }

    const bool expects_generic_proof =
        shielded::v2::UseGenericV2ProofEnvelope(consensus, validation_height);
    const auto proof_kind = bundle.header.proof_envelope.proof_kind;

    switch (proof_kind) {
    case shielded::v2::ProofKind::GENERIC_OPAQUE:
        if (!expects_generic_proof ||
            semantic_family == shielded::v2::TransactionFamily::V2_GENERIC) {
            reject_reason = "bad-shielded-v2-proof-wire";
            return false;
        }
        return true;
    case shielded::v2::ProofKind::GENERIC_SMILE:
    case shielded::v2::ProofKind::GENERIC_BRIDGE:
    case shielded::v2::ProofKind::DIRECT_SMILE:
    case shielded::v2::ProofKind::BATCH_SMILE:
    case shielded::v2::ProofKind::IMPORTED_RECEIPT:
    case shielded::v2::ProofKind::IMPORTED_CLAIM:
        if (expects_generic_proof) {
            reject_reason = "bad-shielded-v2-proof-wire";
            return false;
        }
        return true;
    case shielded::v2::ProofKind::NONE:
    case shielded::v2::ProofKind::DIRECT_MATRICT:
    case shielded::v2::ProofKind::BATCH_MATRICT:
        return true;
    }
    return true;
}

[[nodiscard]] bool RejectMismatchedV2SettlementBindingForFork(
    const shielded::v2::TransactionBundle& bundle,
    shielded::v2::TransactionFamily semantic_family,
    const Consensus::Params* consensus,
    int32_t validation_height,
    std::string& reject_reason)
{
    if (consensus == nullptr) {
        return true;
    }

    const bool expects_generic_binding =
        shielded::v2::UseGenericV2SettlementBinding(consensus, validation_height);
    const auto binding_kind = bundle.header.proof_envelope.settlement_binding_kind;
    switch (semantic_family) {
    case shielded::v2::TransactionFamily::V2_SEND:
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_REBALANCE:
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
        if (expects_generic_binding !=
            shielded::v2::IsGenericPostforkSettlementBindingKind(binding_kind)) {
            reject_reason = "bad-shielded-v2-binding-wire";
            return false;
        }
        return true;
    case shielded::v2::TransactionFamily::V2_GENERIC:
        return true;
    }
    return true;
}

[[nodiscard]] std::optional<std::vector<uint256>> CollectCanonicalProofReceiptIds(
    Span<const shielded::BridgeProofReceipt> receipts,
    std::string& reject_reason);

[[nodiscard]] std::optional<shielded::v2::proof::SettlementContext> ParseV2EgressImportedReceiptContext(
    const shielded::v2::TransactionBundle& bundle,
    std::string& reject_reason)
{
    if (!shielded::v2::BundleHasSemanticFamily(bundle, shielded::v2::TransactionFamily::V2_EGRESS_BATCH) ||
        !std::holds_alternative<shielded::v2::EgressBatchPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-v2-egress-context";
        return std::nullopt;
    }
    if (bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::IMPORTED_RECEIPT &&
        bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::GENERIC_BRIDGE &&
        bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::GENERIC_OPAQUE) {
        reject_reason = "bad-shielded-v2-egress-proof-kind";
        return std::nullopt;
    }
    if (bundle.proof_shards.size() != 1) {
        reject_reason = "bad-v2-settlement-proof-shards";
        return std::nullopt;
    }

    auto receipt = shielded::v2::proof::ParseImportedSettlementReceipt(bundle.header.proof_envelope,
                                                                       bundle.proof_shards.front(),
                                                                       reject_reason);
    if (!receipt.has_value()) return std::nullopt;

    auto witness = shielded::v2::proof::ParseSettlementWitness(bundle.proof_payload, reject_reason);
    if (!witness.has_value()) return std::nullopt;

    shielded::v2::proof::SettlementContext context;
    context.material.statement.domain = shielded::v2::proof::VerificationDomain::BATCH_SETTLEMENT;
    context.material.statement.envelope = bundle.header.proof_envelope;
    context.material.payload_location = shielded::v2::proof::PayloadLocation::INLINE_WITNESS;
    context.material.proof_shards = bundle.proof_shards;
    context.material.proof_payload = bundle.proof_payload;
    context.imported_receipt = *receipt;
    context.descriptor = shielded::BridgeProofDescriptor{receipt->proof_system_id, receipt->verifier_key_hash};
    if (witness->statement.verifier_set.IsValid() ||
        !witness->signed_receipts.empty() ||
        !witness->signed_receipt_proofs.empty()) {
        context.verification_bundle = shielded::BuildBridgeVerificationBundle(
            Span<const shielded::BridgeBatchReceipt>{witness->signed_receipts.data(), witness->signed_receipts.size()},
            Span<const shielded::BridgeProofReceipt>{witness->proof_receipts.data(), witness->proof_receipts.size()});
        if (!context.verification_bundle.has_value()) {
            reject_reason = "bad-v2-settlement-verification-bundle";
            return std::nullopt;
        }
    }

    if (!context.IsValid()) {
        reject_reason = "bad-v2-settlement-context";
        return std::nullopt;
    }
    return context;
}

[[nodiscard]] bool VerifyV2EgressImportedReceiptBundle(const shielded::v2::TransactionBundle& bundle,
                                                       const shielded::v2::proof::SettlementContext& context,
                                                       const shielded::v2::proof::SettlementWitness& witness,
                                                       std::string& reject_reason)
{
    const auto& payload = std::get<shielded::v2::EgressBatchPayload>(bundle.payload);
    if (witness.statement.direction != shielded::BridgeDirection::BRIDGE_OUT) {
        reject_reason = "bad-shielded-v2-egress-direction";
        return false;
    }
    if (witness.statement.entry_count != payload.outputs.size()) {
        reject_reason = "bad-shielded-v2-egress-count";
        return false;
    }
    if (witness.statement.batch_root != payload.egress_root) {
        reject_reason = "bad-shielded-v2-egress-root";
        return false;
    }
    auto receipt_ids = CollectCanonicalProofReceiptIds(
        Span<const shielded::BridgeProofReceipt>{witness.proof_receipts.data(), witness.proof_receipts.size()},
        reject_reason);
    if (!receipt_ids.has_value() || !context.imported_receipt.has_value()) {
        reject_reason = "bad-shielded-v2-egress-binding";
        return false;
    }
    const uint256 imported_receipt_id =
        shielded::ComputeBridgeProofReceiptHash(*context.imported_receipt);
    if (imported_receipt_id.IsNull() ||
        std::find(receipt_ids->begin(), receipt_ids->end(), imported_receipt_id) == receipt_ids->end()) {
        reject_reason = "bad-shielded-v2-egress-binding";
        return false;
    }

    std::optional<shielded::BridgeExternalAnchor> anchor;
    if (context.verification_bundle.has_value()) {
        anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(
            witness.statement,
            Span<const shielded::BridgeBatchReceipt>{witness.signed_receipts.data(), witness.signed_receipts.size()},
            Span<const shielded::BridgeProofReceipt>{witness.proof_receipts.data(), witness.proof_receipts.size()});
    } else {
        anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(
            witness.statement,
            Span<const shielded::BridgeProofReceipt>{witness.proof_receipts.data(), witness.proof_receipts.size()});
    }
    if (!anchor.has_value()) {
        reject_reason = "bad-v2-settlement-proof-anchor";
        return false;
    }
    if (payload.settlement_anchor != shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*anchor)) {
        reject_reason = "bad-shielded-v2-egress-anchor";
        return false;
    }
    if (!context.imported_receipt.has_value() ||
        payload.settlement_binding_digest != shielded::ComputeBridgeProofReceiptHash(*context.imported_receipt)) {
        reject_reason = "bad-shielded-v2-egress-binding";
        return false;
    }

    return true;
}

[[nodiscard]] std::optional<shielded::v2::proof::SettlementContext> ParseV2SettlementAnchorImportedReceiptContext(
    const shielded::v2::TransactionBundle& bundle,
    std::string& reject_reason)
{
    if (!shielded::v2::BundleHasSemanticFamily(bundle, shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR) ||
        !std::holds_alternative<shielded::v2::SettlementAnchorPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-v2-settlement-anchor-context";
        return std::nullopt;
    }
    if (bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::IMPORTED_RECEIPT &&
        bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::GENERIC_BRIDGE &&
        bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::GENERIC_OPAQUE) {
        reject_reason = "bad-shielded-v2-settlement-anchor-proof-kind";
        return std::nullopt;
    }
    if (bundle.proof_shards.size() != 1) {
        reject_reason = "bad-v2-settlement-proof-shards";
        return std::nullopt;
    }

    auto receipt = shielded::v2::proof::ParseImportedSettlementReceipt(bundle.header.proof_envelope,
                                                                       bundle.proof_shards.front(),
                                                                       reject_reason);
    if (!receipt.has_value()) return std::nullopt;

    auto witness = shielded::v2::proof::ParseSettlementWitness(bundle.proof_payload, reject_reason);
    if (!witness.has_value()) return std::nullopt;

    shielded::v2::proof::SettlementContext context;
    context.material.statement.domain = shielded::v2::proof::VerificationDomain::BATCH_SETTLEMENT;
    context.material.statement.envelope = bundle.header.proof_envelope;
    context.material.payload_location = shielded::v2::proof::PayloadLocation::INLINE_WITNESS;
    context.material.proof_shards = bundle.proof_shards;
    context.material.proof_payload = bundle.proof_payload;
    context.imported_receipt = *receipt;
    context.descriptor = shielded::BridgeProofDescriptor{receipt->proof_system_id, receipt->verifier_key_hash};
    if (witness->statement.verifier_set.IsValid() ||
        !witness->signed_receipts.empty() ||
        !witness->signed_receipt_proofs.empty()) {
        context.verification_bundle = shielded::BuildBridgeVerificationBundle(
            Span<const shielded::BridgeBatchReceipt>{witness->signed_receipts.data(), witness->signed_receipts.size()},
            Span<const shielded::BridgeProofReceipt>{witness->proof_receipts.data(), witness->proof_receipts.size()});
        if (!context.verification_bundle.has_value()) {
            reject_reason = "bad-v2-settlement-verification-bundle";
            return std::nullopt;
        }
    }

    if (!context.IsValid()) {
        reject_reason = "bad-v2-settlement-context";
        return std::nullopt;
    }
    return context;
}

[[nodiscard]] std::optional<shielded::v2::proof::SettlementContext> ParseV2SettlementAnchorImportedClaimContext(
    const shielded::v2::TransactionBundle& bundle,
    std::string& reject_reason)
{
    if (!shielded::v2::BundleHasSemanticFamily(bundle, shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR) ||
        !std::holds_alternative<shielded::v2::SettlementAnchorPayload>(bundle.payload)) {
        reject_reason = "bad-shielded-v2-settlement-anchor-context";
        return std::nullopt;
    }
    if (bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::IMPORTED_CLAIM &&
        bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::GENERIC_BRIDGE &&
        bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::GENERIC_OPAQUE) {
        reject_reason = "bad-shielded-v2-settlement-anchor-proof-kind";
        return std::nullopt;
    }
    if (bundle.proof_shards.size() != 1) {
        reject_reason = "bad-v2-settlement-proof-shards";
        return std::nullopt;
    }

    auto claim = shielded::v2::proof::ParseImportedSettlementClaim(bundle.header.proof_envelope,
                                                                   bundle.proof_shards.front(),
                                                                   reject_reason);
    if (!claim.has_value()) return std::nullopt;

    shielded::v2::proof::SettlementContext context;
    context.material.statement.domain = shielded::v2::proof::VerificationDomain::BATCH_SETTLEMENT;
    context.material.statement.envelope = bundle.header.proof_envelope;
    context.material.payload_location = shielded::v2::proof::PayloadLocation::INLINE_WITNESS;
    context.material.proof_shards = bundle.proof_shards;
    context.material.proof_payload = bundle.proof_payload;
    context.imported_claim = *claim;

    if (!context.IsValid()) {
        reject_reason = "bad-v2-settlement-context";
        return std::nullopt;
    }
    return context;
}

[[nodiscard]] std::optional<std::vector<uint256>> CollectCanonicalProofReceiptIds(
    Span<const shielded::BridgeProofReceipt> receipts,
    std::string& reject_reason)
{
    std::vector<uint256> receipt_ids;
    receipt_ids.reserve(receipts.size());
    for (const auto& receipt : receipts) {
        const uint256 receipt_id = shielded::ComputeBridgeProofReceiptHash(receipt);
        if (receipt_id.IsNull()) {
            reject_reason = "bad-shielded-v2-settlement-anchor-receipts";
            return std::nullopt;
        }
        receipt_ids.push_back(receipt_id);
    }
    std::sort(receipt_ids.begin(), receipt_ids.end());
    if (std::adjacent_find(receipt_ids.begin(), receipt_ids.end()) != receipt_ids.end()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-receipts";
        return std::nullopt;
    }
    return receipt_ids;
}

[[nodiscard]] std::optional<std::vector<uint256>> CollectCanonicalProofAdapterIds(
    Span<const shielded::BridgeProofAdapter> adapters,
    std::string& reject_reason)
{
    std::vector<uint256> adapter_ids;
    adapter_ids.reserve(adapters.size());
    for (const auto& adapter : adapters) {
        const uint256 adapter_id = shielded::ComputeBridgeProofAdapterId(adapter);
        if (adapter_id.IsNull()) {
            reject_reason = "bad-shielded-v2-settlement-anchor-adapters";
            return std::nullopt;
        }
        adapter_ids.push_back(adapter_id);
    }
    std::sort(adapter_ids.begin(), adapter_ids.end());
    if (std::adjacent_find(adapter_ids.begin(), adapter_ids.end()) != adapter_ids.end()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-adapters";
        return std::nullopt;
    }
    return adapter_ids;
}

[[nodiscard]] bool UseBridgeProofSystemAllowlist(const Consensus::Params* consensus, int32_t validation_height)
{
    return consensus != nullptr && consensus->IsShieldedMatRiCTDisabled(validation_height);
}

[[nodiscard]] bool RequireCanonicalBridgeProofSystems(
    Span<const shielded::BridgeProofReceipt> proof_receipts,
    Span<const shielded::BridgeProofAdapter> imported_adapters,
    std::string& reject_reason)
{
    for (const auto& receipt : proof_receipts) {
        if (!shielded::IsCanonicalBridgeProofSystemId(receipt.proof_system_id)) {
            reject_reason = "bad-shielded-bridge-proof-system-id";
            return false;
        }
    }
    for (const auto& adapter : imported_adapters) {
        if (!shielded::IsCanonicalBridgeProofSystemId(
                shielded::ComputeBridgeProofSystemId(adapter.profile))) {
            reject_reason = "bad-shielded-bridge-proof-system-id";
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool VerifySettlementAnchorReserveBinding(
    const shielded::v2::SettlementAnchorPayload& payload,
    std::string& reject_reason)
{
    if (!shielded::v2::ReserveDeltaSetIsCanonical(
            Span<const shielded::v2::ReserveDelta>{payload.reserve_deltas.data(), payload.reserve_deltas.size()}) ||
        (payload.reserve_deltas.empty() && !payload.anchored_netting_manifest_id.IsNull())) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }
    return true;
}

[[nodiscard]] bool VerifyV2SettlementAnchorImportedReceiptBundle(
    const shielded::v2::TransactionBundle& bundle,
    const shielded::v2::proof::SettlementContext& context,
    const shielded::v2::proof::SettlementWitness& witness,
    uint256& settlement_anchor_digest,
    std::string& reject_reason)
{
    const auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
    if (witness.statement.direction != shielded::BridgeDirection::BRIDGE_OUT) {
        reject_reason = "bad-shielded-v2-settlement-anchor-direction";
        return false;
    }
    if (!payload.imported_claim_ids.empty()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }
    if (!VerifySettlementAnchorReserveBinding(payload, reject_reason)) return false;

    const uint256 statement_digest = shielded::ComputeBridgeBatchStatementHash(witness.statement);
    if (statement_digest.IsNull() ||
        payload.batch_statement_digests.size() != 1 ||
        payload.batch_statement_digests.front() != statement_digest) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }

    auto receipt_ids = CollectCanonicalProofReceiptIds(
        Span<const shielded::BridgeProofReceipt>{witness.proof_receipts.data(), witness.proof_receipts.size()},
        reject_reason);
    if (!receipt_ids.has_value()) return false;
    auto adapter_ids = CollectCanonicalProofAdapterIds(
        Span<const shielded::BridgeProofAdapter>{witness.imported_adapters.data(), witness.imported_adapters.size()},
        reject_reason);
    if (!adapter_ids.has_value()) return false;

    if (payload.proof_receipt_ids != *receipt_ids ||
        payload.imported_adapter_ids != *adapter_ids ||
        !context.imported_receipt.has_value() ||
        std::find(receipt_ids->begin(),
                  receipt_ids->end(),
                  shielded::ComputeBridgeProofReceiptHash(*context.imported_receipt)) == receipt_ids->end()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }

    std::optional<shielded::BridgeExternalAnchor> anchor;
    if (context.verification_bundle.has_value()) {
        anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(
            witness.statement,
            Span<const shielded::BridgeBatchReceipt>{witness.signed_receipts.data(), witness.signed_receipts.size()},
            Span<const shielded::BridgeProofReceipt>{witness.proof_receipts.data(), witness.proof_receipts.size()});
    } else {
        anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(
            witness.statement,
            Span<const shielded::BridgeProofReceipt>{witness.proof_receipts.data(), witness.proof_receipts.size()});
    }
    if (!anchor.has_value()) {
        reject_reason = "bad-v2-settlement-proof-anchor";
        return false;
    }
    settlement_anchor_digest = shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*anchor);
    if (settlement_anchor_digest.IsNull()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }
    return true;
}

[[nodiscard]] bool VerifyV2SettlementAnchorImportedClaimBundle(
    const shielded::v2::TransactionBundle& bundle,
    const shielded::v2::proof::SettlementContext& context,
    const shielded::v2::proof::SettlementWitness& witness,
    uint256& settlement_anchor_digest,
    std::string& reject_reason)
{
    const auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle.payload);
    if (witness.statement.direction != shielded::BridgeDirection::BRIDGE_OUT) {
        reject_reason = "bad-shielded-v2-settlement-anchor-direction";
        return false;
    }
    if (!payload.proof_receipt_ids.empty()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }
    if (!VerifySettlementAnchorReserveBinding(payload, reject_reason)) return false;

    const uint256 statement_digest = shielded::ComputeBridgeBatchStatementHash(witness.statement);
    if (statement_digest.IsNull() ||
        payload.batch_statement_digests.size() != 1 ||
        payload.batch_statement_digests.front() != statement_digest) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }

    if (!context.imported_claim.has_value()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }
    auto adapter_ids = CollectCanonicalProofAdapterIds(
        Span<const shielded::BridgeProofAdapter>{witness.imported_adapters.data(), witness.imported_adapters.size()},
        reject_reason);
    if (!adapter_ids.has_value()) return false;
    const uint256 claim_id = shielded::ComputeBridgeProofClaimHash(*context.imported_claim);
    if (claim_id.IsNull() ||
        payload.imported_claim_ids.size() != 1 ||
        payload.imported_claim_ids.front() != claim_id ||
        payload.imported_adapter_ids != *adapter_ids) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }

    const auto anchor = shielded::BuildBridgeExternalAnchorFromClaim(witness.statement,
                                                                     *context.imported_claim);
    if (!anchor.has_value()) {
        reject_reason = "bad-v2-settlement-proof-anchor";
        return false;
    }
    settlement_anchor_digest = shielded::v2::proof::ComputeSettlementExternalAnchorDigest(*anchor);
    if (settlement_anchor_digest.IsNull()) {
        reject_reason = "bad-shielded-v2-settlement-anchor-binding";
        return false;
    }
    return true;
}

/**
 * Attempt to parse a proof payload as a SMILE v2 CT proof.
 * Returns true and populates nullifiers on success, false if the bytes
 * do not look like a valid SMILE proof (caller should fall back to MatRiCT).
 */
[[nodiscard]] [[maybe_unused]] bool TryParseAsSmile2Proof(
    const std::vector<uint8_t>& proof_bytes,
    size_t num_inputs,
    size_t num_outputs,
    std::vector<Nullifier>& out_nullifiers,
    std::string& reject_reason)
{
    // SMILE v2 proofs are typically 8-30 KB; reject trivially small buffers.
    if (proof_bytes.size() < smile2::MIN_SMILE2_PROOF_BYTES ||
        proof_bytes.size() > smile2::MAX_SMILE2_PROOF_BYTES) {
        return false;
    }

    smile2::SmileCTProof ct_proof;
    auto parse_err = smile2::ParseSmile2Proof(proof_bytes, num_inputs, num_outputs, ct_proof);
    if (parse_err.has_value()) {
        // Not a valid SMILE proof — let caller try MatRiCT.
        return false;
    }

    // Extract serial numbers as nullifiers.
    std::vector<smile2::SmilePoly> serials;
    auto extract_err = smile2::ExtractSmile2SerialNumbers(ct_proof, serials);
    if (extract_err.has_value()) {
        reject_reason = "bad-shielded-smile2-serial-extract";
        return false;
    }
    if (serials.size() != num_inputs) {
        reject_reason = "bad-shielded-smile2-serial-count";
        return false;
    }

    out_nullifiers.clear();
    out_nullifiers.reserve(num_inputs);
    for (const auto& sn : serials) {
        uint256 nf = smile2::ComputeSmileSerialHash(sn);
        if (nf.IsNull()) {
            reject_reason = "bad-shielded-smile2-nullifier-zero";
            return false;
        }
        out_nullifiers.push_back(nf);
    }

    return true;
}

/**
 * Check proof plausibility for SMILE v2 proofs.
 * SMILE proofs are ~8-30 KB vs MatRiCT's ~50 KB+ per input, so
 * we use lower per-input/output thresholds.
 */
[[nodiscard]] [[maybe_unused]] bool IsSmile2ProofPlausible(size_t proof_size,
                                           size_t num_inputs,
                                           size_t num_outputs)
{
    // SMILE v2 lower bounds (well below actual sizes to avoid false rejects):
    //   Base overhead: 1 KB (Fiat-Shamir seeds, h2, aux commitment)
    //   Per input: 4 KB (z0 + w0 + serial number polynomial)
    //   Per output: 2 KB (output coin commitment)
    static constexpr size_t kSmileMinBase{1024};
    static constexpr size_t kSmileMinPerInput{4096};
    static constexpr size_t kSmileMinPerOutput{2048};

    size_t min_expected = kSmileMinBase;
    const size_t input_bytes = num_inputs * kSmileMinPerInput;
    if (input_bytes / kSmileMinPerInput != num_inputs) return false;  // overflow
    min_expected += input_bytes;
    const size_t output_bytes = num_outputs * kSmileMinPerOutput;
    if (output_bytes / kSmileMinPerOutput != num_outputs) return false;
    min_expected += output_bytes;

    return proof_size >= min_expected && proof_size <= smile2::MAX_SMILE2_PROOF_BYTES;
}

} // namespace

std::optional<std::shared_ptr<const MatRiCTProof>> ParseShieldedSpendAuthProof(
    const CShieldedBundle& bundle,
    std::string& reject_reason)
{
    std::optional<std::shared_ptr<const MatRiCTProof>> parsed;
    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        if (v2_bundle == nullptr ||
            !shielded::v2::BundleHasSemanticFamily(*v2_bundle, shielded::v2::TransactionFamily::V2_SEND)) {
            reject_reason = "bad-shielded-spend-auth-proof";
            return std::nullopt;
        }

        const auto& envelope = v2_bundle->header.proof_envelope;
        if (envelope.proof_kind == shielded::v2::ProofKind::DIRECT_SMILE ||
            envelope.proof_kind == shielded::v2::ProofKind::GENERIC_SMILE ||
            envelope.proof_kind == shielded::v2::ProofKind::GENERIC_OPAQUE) {
            return std::shared_ptr<const MatRiCTProof>{};
        }
        if (envelope.proof_kind == shielded::v2::ProofKind::BATCH_SMILE ||
            envelope.proof_kind == shielded::v2::ProofKind::GENERIC_BRIDGE ||
            envelope.proof_kind == shielded::v2::ProofKind::GENERIC_OPAQUE ||
            (envelope.proof_kind == shielded::v2::ProofKind::GENERIC_SMILE &&
             !shielded::v2::BundleHasSemanticFamily(*v2_bundle, shielded::v2::TransactionFamily::V2_SEND))) {
            reject_reason = MapSpendAuthReject("bad-shielded-proof-unsupported");
            return std::nullopt;
        }

        parsed = shielded::v2::proof::ParseV2SendNativeProof(*v2_bundle, reject_reason);
    } else {
        parsed = shielded::v2::proof::ParseLegacyDirectSpendNativeProof(bundle, reject_reason);
    }
    if (!parsed.has_value()) {
        reject_reason = MapSpendAuthReject(reject_reason);
        return std::nullopt;
    }
    return parsed;
}

std::optional<std::vector<Nullifier>> ExtractShieldedProofBoundNullifiers(
    const MatRiCTProof& proof,
    size_t expected_input_count,
    std::string& reject_reason)
{
    auto nullifiers = shielded::v2::proof::ExtractBoundNullifiers(proof, expected_input_count, reject_reason);
    if (!nullifiers.has_value()) {
        reject_reason = MapSpendAuthReject(reject_reason);
        return std::nullopt;
    }
    return nullifiers;
}

std::optional<std::vector<Nullifier>> ExtractShieldedProofBoundNullifiers(
    const CShieldedBundle& bundle,
    std::string& reject_reason,
    bool reject_rice_codec)
{
    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        if (v2_bundle != nullptr) {
            const auto& envelope = v2_bundle->header.proof_envelope;
            if (envelope.proof_kind == shielded::v2::ProofKind::NONE) {
                return std::vector<Nullifier>{};
            }
            if ((envelope.proof_kind == shielded::v2::ProofKind::DIRECT_SMILE ||
                 envelope.proof_kind == shielded::v2::ProofKind::GENERIC_SMILE ||
                 envelope.proof_kind == shielded::v2::ProofKind::GENERIC_OPAQUE) &&
                shielded::v2::BundleHasSemanticFamily(*v2_bundle,
                                                      shielded::v2::TransactionFamily::V2_SEND)) {
                auto witness = shielded::v2::proof::ParseV2SendWitness(*v2_bundle, reject_reason);
                if (!witness.has_value()) {
                    reject_reason = MapSpendAuthReject(reject_reason);
                    return std::nullopt;
                }
                const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);

                smile2::SmileCTProof proof;
                auto parse_err = smile2::ParseSmile2Proof(witness->smile_proof_bytes,
                                                          witness->spends.size(),
                                                          payload.outputs.size(),
                                                          proof,
                                                          reject_rice_codec);
                if (parse_err.has_value()) {
                    reject_reason = MapSpendAuthReject(*parse_err);
                    return std::nullopt;
                }

                std::vector<smile2::SmilePoly> serial_numbers;
                auto extract_err = smile2::ExtractSmile2SerialNumbers(proof, serial_numbers);
                if (extract_err.has_value()) {
                    reject_reason = MapSpendAuthReject(*extract_err);
                    return std::nullopt;
                }

                std::vector<Nullifier> out;
                out.reserve(serial_numbers.size());
                for (const auto& serial : serial_numbers) {
                    const Nullifier nullifier = smile2::ComputeSmileSerialHash(serial);
                    if (nullifier.IsNull()) {
                        reject_reason = MapSpendAuthReject("bad-smile2-proof-nullifier");
                        return std::nullopt;
                    }
                    out.push_back(nullifier);
                }
                return out;
            }
            if (envelope.proof_kind == shielded::v2::ProofKind::BATCH_SMILE ||
                envelope.proof_kind == shielded::v2::ProofKind::GENERIC_BRIDGE ||
                (envelope.proof_kind == shielded::v2::ProofKind::GENERIC_OPAQUE &&
                 !shielded::v2::BundleHasSemanticFamily(*v2_bundle,
                                                        shielded::v2::TransactionFamily::V2_SEND)) ||
                (envelope.proof_kind == shielded::v2::ProofKind::GENERIC_SMILE &&
                 !shielded::v2::BundleHasSemanticFamily(*v2_bundle, shielded::v2::TransactionFamily::V2_SEND))) {
                reject_reason = MapSpendAuthReject("bad-shielded-proof-unsupported");
                return std::nullopt;
            }
        }
    }

    auto parsed = ParseShieldedSpendAuthProof(bundle, reject_reason);
    if (!parsed.has_value()) return std::nullopt;
    return ExtractShieldedProofBoundNullifiers(**parsed, bundle.GetShieldedInputCount(), reject_reason);
}

std::optional<std::vector<uint256>> ExtractCreatedShieldedSettlementAnchors(
    const CTransaction& tx,
    std::string& reject_reason)
{
    if (!tx.HasShieldedBundle()) return std::vector<uint256>{};

    const CShieldedBundle& bundle = tx.GetShieldedBundle();
    if (!bundle.HasV2Bundle()) return std::vector<uint256>{};

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr ||
        !shielded::v2::BundleHasSemanticFamily(*v2_bundle, shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR)) {
        return std::vector<uint256>{};
    }

    auto witness = shielded::v2::proof::ParseSettlementWitness(v2_bundle->proof_payload, reject_reason);
    if (!witness.has_value()) return std::nullopt;

    uint256 settlement_anchor_digest;
    switch (v2_bundle->header.proof_envelope.proof_kind) {
    case shielded::v2::ProofKind::IMPORTED_RECEIPT:
    case shielded::v2::ProofKind::GENERIC_BRIDGE:
    case shielded::v2::ProofKind::GENERIC_OPAQUE:
        if (!std::get<shielded::v2::SettlementAnchorPayload>(v2_bundle->payload).imported_claim_ids.empty()) {
            auto context = ParseV2SettlementAnchorImportedClaimContext(*v2_bundle, reject_reason);
            if (!context.has_value()) return std::nullopt;
            if (!shielded::v2::proof::VerifySettlementContext(*context, *witness, reject_reason)) {
                return std::nullopt;
            }
            if (!VerifyV2SettlementAnchorImportedClaimBundle(*v2_bundle,
                                                             *context,
                                                             *witness,
                                                             settlement_anchor_digest,
                                                             reject_reason)) {
                return std::nullopt;
            }
            break;
        }
        {
            auto context = ParseV2SettlementAnchorImportedReceiptContext(*v2_bundle, reject_reason);
            if (!context.has_value()) return std::nullopt;
            if (!shielded::v2::proof::VerifySettlementContext(*context, *witness, reject_reason)) {
                return std::nullopt;
            }
            if (!VerifyV2SettlementAnchorImportedReceiptBundle(*v2_bundle,
                                                               *context,
                                                               *witness,
                                                               settlement_anchor_digest,
                                                               reject_reason)) {
                return std::nullopt;
            }
            break;
        }
    case shielded::v2::ProofKind::IMPORTED_CLAIM: {
        auto context = ParseV2SettlementAnchorImportedClaimContext(*v2_bundle, reject_reason);
        if (!context.has_value()) return std::nullopt;
        if (!shielded::v2::proof::VerifySettlementContext(*context, *witness, reject_reason)) {
            return std::nullopt;
        }
        if (!VerifyV2SettlementAnchorImportedClaimBundle(*v2_bundle,
                                                         *context,
                                                         *witness,
                                                         settlement_anchor_digest,
                                                         reject_reason)) {
            return std::nullopt;
        }
        break;
    }
    default:
        reject_reason = "bad-shielded-v2-settlement-anchor-proof-kind";
        return std::nullopt;
    }

    return std::vector<uint256>{settlement_anchor_digest};
}

std::optional<std::vector<uint256>> ExtractCreatedShieldedNettingManifests(
    const CTransaction& tx,
    std::string& reject_reason)
{
    if (!tx.HasShieldedBundle()) return std::vector<uint256>{};

    const CShieldedBundle& bundle = tx.GetShieldedBundle();
    if (!bundle.HasV2Bundle()) return std::vector<uint256>{};

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr ||
        !shielded::v2::BundleHasSemanticFamily(*v2_bundle, shielded::v2::TransactionFamily::V2_REBALANCE) ||
        !std::holds_alternative<shielded::v2::RebalancePayload>(v2_bundle->payload)) {
        return std::vector<uint256>{};
    }

    const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
    if (!payload.has_netting_manifest) return std::vector<uint256>{};

    const uint256 manifest_id = shielded::v2::ComputeNettingManifestId(payload.netting_manifest);
    if (manifest_id.IsNull()) {
        reject_reason = "bad-shielded-v2-rebalance-manifest";
        return std::nullopt;
    }

    return std::vector<uint256>{manifest_id};
}

std::optional<std::vector<ConfirmedNettingManifestState>> ExtractCreatedShieldedNettingManifestStates(
    const CTransaction& tx,
    int32_t created_height,
    std::string& reject_reason)
{
    if (created_height < 0) {
        reject_reason = "bad-shielded-v2-rebalance-manifest-height";
        return std::nullopt;
    }

    if (!tx.HasShieldedBundle()) return std::vector<ConfirmedNettingManifestState>{};

    const CShieldedBundle& bundle = tx.GetShieldedBundle();
    if (!bundle.HasV2Bundle()) return std::vector<ConfirmedNettingManifestState>{};

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr ||
        !shielded::v2::BundleHasSemanticFamily(*v2_bundle, shielded::v2::TransactionFamily::V2_REBALANCE) ||
        !std::holds_alternative<shielded::v2::RebalancePayload>(v2_bundle->payload)) {
        return std::vector<ConfirmedNettingManifestState>{};
    }

    const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
    if (!payload.has_netting_manifest) return std::vector<ConfirmedNettingManifestState>{};

    const uint256 manifest_id = shielded::v2::ComputeNettingManifestId(payload.netting_manifest);
    if (manifest_id.IsNull() || !payload.netting_manifest.IsValid()) {
        reject_reason = "bad-shielded-v2-rebalance-manifest";
        return std::nullopt;
    }

    return std::vector<ConfirmedNettingManifestState>{ConfirmedNettingManifestState{
        .manifest_id = manifest_id,
        .created_height = created_height,
        .settlement_window = payload.netting_manifest.settlement_window,
    }};
}

CShieldedProofCheck::CShieldedProofCheck(
    const CTransaction& tx,
    std::shared_ptr<const shielded::ShieldedMerkleTree> tree_snapshot,
    std::shared_ptr<const std::map<uint256, smile2::CompactPublicAccount>> smile_public_accounts,
    std::shared_ptr<const std::map<uint256, uint256>> account_leaf_commitments,
    std::shared_ptr<const MatRiCTProof> parsed_proof)
    : CShieldedProofCheck(tx,
                          Params().GetConsensus(),
                          /*validation_height=*/std::numeric_limits<int32_t>::max(),
                          std::move(tree_snapshot),
                          std::move(smile_public_accounts),
                          std::move(account_leaf_commitments),
                          std::move(parsed_proof))
{
}

CShieldedProofCheck::CShieldedProofCheck(const CTransaction& tx,
                                         const Consensus::Params& consensus,
                                         int32_t validation_height,
                                         std::shared_ptr<const shielded::ShieldedMerkleTree> tree_snapshot,
                                         std::shared_ptr<const std::map<uint256, smile2::CompactPublicAccount>> smile_public_accounts,
                                         std::shared_ptr<const std::map<uint256, uint256>> account_leaf_commitments,
                                         std::shared_ptr<const MatRiCTProof> parsed_proof)
    : m_tx(MakeTransactionRef(tx)),
      m_consensus(&consensus),
      m_validation_height(validation_height),
      m_tree_snapshot(std::move(tree_snapshot)),
      m_smile_public_accounts(std::move(smile_public_accounts)),
      m_account_leaf_commitments(std::move(account_leaf_commitments)),
      m_parsed_proof(std::move(parsed_proof))
{
}

std::optional<std::string> CShieldedProofCheck::operator()() const
{
    if (!m_tx || !m_tx->HasShieldedBundle()) return std::string{"bad-shielded-empty"};

    const CShieldedBundle& bundle = m_tx->GetShieldedBundle();
    if (bundle.IsEmpty()) return std::string{"bad-shielded-empty"};
    if (!bundle.CheckStructure()) return std::string{"bad-shielded-bundle"};

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        if (v2_bundle == nullptr) return std::string{"bad-shielded-bundle"};

        const bool reject_rice_codec =
            m_consensus != nullptr &&
            m_consensus->IsShieldedSmileRiceCodecDisabled(m_validation_height);
        const bool bind_smile_anonset_context =
            m_consensus != nullptr &&
            m_consensus->IsShieldedMatRiCTDisabled(m_validation_height);
        const bool reject_matrict =
            m_consensus != nullptr &&
            m_consensus->IsShieldedMatRiCTDisabled(m_validation_height);

        if (m_consensus != nullptr) {
            std::string retired_matrict_reject;
            if (!RejectRetiredMatRiCTEnvelopeAfterDisable(bundle,
                                                          *m_consensus,
                                                          m_validation_height,
                                                          retired_matrict_reject)) {
                return retired_matrict_reject;
            }
        }

        std::string proof_reject;
        if (!RejectMismatchedV2WireFamilyForFork(*v2_bundle,
                                                 m_consensus,
                                                 m_validation_height,
                                                 proof_reject)) {
            return proof_reject;
        }

        if (reject_matrict) {
            switch (v2_bundle->header.proof_envelope.proof_kind) {
            case shielded::v2::ProofKind::DIRECT_MATRICT:
            case shielded::v2::ProofKind::BATCH_MATRICT:
                return std::string{"bad-shielded-matrict-disabled"};
            default:
                break;
            }
        }

        const auto semantic_family = shielded::v2::GetBundleSemanticFamily(*v2_bundle);
        if (!RejectMismatchedV2ProofEnvelopeForFork(*v2_bundle,
                                                    semantic_family,
                                                    m_consensus,
                                                    m_validation_height,
                                                    proof_reject)) {
            return proof_reject;
        }
        if (!RejectMismatchedV2SettlementBindingForFork(*v2_bundle,
                                                        semantic_family,
                                                        m_consensus,
                                                        m_validation_height,
                                                        proof_reject)) {
            return proof_reject;
        }
        switch (semantic_family) {
        case shielded::v2::TransactionFamily::V2_LIFECYCLE: {
            if (m_consensus == nullptr ||
                !m_consensus->IsShieldedMatRiCTDisabled(m_validation_height)) {
                return std::string{"bad-shielded-v2-lifecycle-disabled"};
            }

            const auto& payload = std::get<shielded::v2::LifecyclePayload>(v2_bundle->payload);
            if (bundle.HasShieldedInputs() ||
                bundle.HasShieldedOutputs() ||
                v2_bundle->header.proof_envelope.proof_kind != shielded::v2::ProofKind::NONE ||
                !v2_bundle->proof_shards.empty() ||
                !v2_bundle->proof_payload.empty()) {
                return std::string{"bad-shielded-proof"};
            }
            if (m_tx->vin.empty()) {
                return std::string{"bad-shielded-v2-lifecycle-transparent-input"};
            }
            if (payload.transparent_binding_digest !=
                shielded::v2::ComputeV2LifecycleTransparentBindingDigest(*m_tx)) {
                return std::string{"bad-shielded-v2-lifecycle-binding"};
            }
            return std::nullopt;
        }
        case shielded::v2::TransactionFamily::V2_SEND: {
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            if (!RejectPostForkDirectSendPublicFlow(payload,
                                                    *m_tx,
                                                    m_consensus,
                                                    m_validation_height,
                                                    proof_reject)) {
                return proof_reject;
            }
            if (!RejectDirectSendEncodingForFork(payload,
                                                 m_consensus,
                                                 m_validation_height,
                                                 proof_reject)) {
                return proof_reject;
            }
            if (payload.spends.empty()) {
                if (v2_bundle->header.proof_envelope.proof_kind != shielded::v2::ProofKind::NONE ||
                    !v2_bundle->proof_payload.empty() ||
                    m_tx->vin.empty()) {
                    return std::string{"bad-shielded-proof"};
                }
                return std::nullopt;
            }

            if (!bundle.HasShieldedInputs()) return std::string{"bad-shielded-proof-missing"};
            if (!m_tree_snapshot) return std::string{"bad-shielded-ring-tree-unavailable"};
            if (!m_tx->vin.empty()) {
                return std::string{"bad-shielded-v2-transparent-input"};
            }
            if (!RejectShieldedCanonicalFeeBucket(semantic_family,
                                                  payload.fee,
                                                  m_consensus,
                                                  m_validation_height,
                                                  proof_reject)) {
                return proof_reject;
            }

            std::optional<uint256> expected_extension_digest;
            if (m_consensus != nullptr &&
                m_consensus->IsShieldedTxBindingActive(m_validation_height)) {
                expected_extension_digest = shielded::v2::proof::ComputeV2SendExtensionDigest(*m_tx);
            }
            const shielded::v2::proof::ProofStatement statement =
                m_consensus != nullptr
                    ? shielded::v2::proof::DescribeV2SendStatement(
                          *m_tx,
                          *m_consensus,
                          m_validation_height,
                          expected_extension_digest)
                    : shielded::v2::proof::DescribeV2SendStatement(*m_tx, expected_extension_digest);
            auto context = shielded::v2::proof::ParseV2SendProof(*v2_bundle, statement, proof_reject);
            if (!context.has_value()) {
                LogPrintf("CShieldedProofCheck v2_send parse failed txid=%s reject=%s statement=%s tree_root=%s tree_size=%u\n",
                          m_tx->GetHash().ToString(),
                          proof_reject,
                          statement.envelope.statement_digest.ToString(),
                          m_tree_snapshot->Root().ToString(),
                          static_cast<unsigned int>(m_tree_snapshot->Size()));
                return proof_reject;
            }
            const size_t ring_size = context->witness.spends.empty()
                ? 0
                : context->witness.spends.front().ring_positions.size();
            if (!RejectShieldedMinimumPrivacyPool(ring_size,
                                                  m_tree_snapshot->Size(),
                                                  m_consensus,
                                                  m_validation_height,
                                                  proof_reject)) {
                return proof_reject;
            }
            if (!context->IsValid(payload.spends.size(), payload.outputs.size())) {
                LogPrintf("CShieldedProofCheck v2_send invalid context txid=%s spends=%u outputs=%u witness_spends=%u tree_root=%s tree_size=%u\n",
                          m_tx->GetHash().ToString(),
                          static_cast<unsigned int>(payload.spends.size()),
                          static_cast<unsigned int>(payload.outputs.size()),
                          static_cast<unsigned int>(context->witness.spends.size()),
                          m_tree_snapshot->Root().ToString(),
                          static_cast<unsigned int>(m_tree_snapshot->Size()));
                return std::string{"bad-shielded-proof"};
            }

            if (context->witness.use_smile) {
                if (!m_smile_public_accounts || !m_account_leaf_commitments) {
                    return std::string{"bad-smile2-ring-member-account"};
                }
                if (reject_rice_codec) {
                    smile2::SmileCTProof proof;
                    if (auto parse_err = smile2::ParseSmile2Proof(context->witness.smile_proof_bytes,
                                                                  payload.spends.size(),
                                                                  payload.outputs.size(),
                                                                  proof,
                                                                  /*reject_rice_codec=*/true);
                        parse_err.has_value()) {
                        return *parse_err;
                    }
                }
                std::string ring_member_error;
                auto smile_ring_members =
                    shielded::v2::proof::BuildV2SendSmileRingMembers(*v2_bundle,
                                                                     *context,
                                                                     *m_tree_snapshot,
                                                                     *m_smile_public_accounts,
                                                                     *m_account_leaf_commitments,
                                                                     ring_member_error);
                if (!smile_ring_members.has_value()) {
                    LogPrintf("CShieldedProofCheck v2_send SMILE ring reconstruction failed txid=%s reject=%s statement=%s tree_root=%s tree_size=%u smile_accounts=%u\n",
                              m_tx->GetHash().ToString(),
                              ring_member_error,
                              statement.envelope.statement_digest.ToString(),
                              m_tree_snapshot->Root().ToString(),
                              static_cast<unsigned int>(m_tree_snapshot->Size()),
                              static_cast<unsigned int>(m_smile_public_accounts->size()));
                    return ring_member_error;
                }
                if (!shielded::v2::proof::VerifyV2SendProof(*v2_bundle,
                                                            *context,
                                                            *smile_ring_members,
                                                            reject_rice_codec,
                                                            bind_smile_anonset_context)) {
                    LogPrintf("CShieldedProofCheck v2_send SMILE verify failed txid=%s statement=%s anchor=%s fee=%lld tree_root=%s tree_size=%u\n",
                              m_tx->GetHash().ToString(),
                              statement.envelope.statement_digest.ToString(),
                              payload.spend_anchor.ToString(),
                              static_cast<long long>(payload.fee),
                              m_tree_snapshot->Root().ToString(),
                              static_cast<unsigned int>(m_tree_snapshot->Size()));
                    return std::string{"bad-shielded-proof"};
                }
            } else {
                std::string ring_member_error;
                auto ring_members = shielded::v2::proof::BuildV2SendRingMembers(*v2_bundle,
                                                                                *context,
                                                                                *m_tree_snapshot,
                                                                                ring_member_error);
                if (!ring_members.has_value()) {
                    LogPrintf("CShieldedProofCheck v2_send ring reconstruction failed txid=%s reject=%s statement=%s tree_root=%s tree_size=%u\n",
                              m_tx->GetHash().ToString(),
                              ring_member_error,
                              statement.envelope.statement_digest.ToString(),
                              m_tree_snapshot->Root().ToString(),
                              static_cast<unsigned int>(m_tree_snapshot->Size()));
                    return ring_member_error;
                }
                if (!shielded::v2::proof::VerifyV2SendProof(*v2_bundle, *context, *ring_members)) {
                    LogPrintf("CShieldedProofCheck v2_send verify failed txid=%s statement=%s anchor=%s fee=%lld tree_root=%s tree_size=%u\n",
                              m_tx->GetHash().ToString(),
                              statement.envelope.statement_digest.ToString(),
                              payload.spend_anchor.ToString(),
                              static_cast<long long>(payload.fee),
                              m_tree_snapshot->Root().ToString(),
                              static_cast<unsigned int>(m_tree_snapshot->Size()));
                    return std::string{"bad-shielded-proof"};
                }
            }
            return std::nullopt;
        }
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            std::string proof_reject;
            if (!bundle.HasShieldedInputs()) return std::string{"bad-shielded-proof-missing"};
            if (!m_tree_snapshot) return std::string{"bad-shielded-ring-tree-unavailable"};
            if (!m_tx->vin.empty() || !m_tx->vout.empty()) {
                return std::string{"bad-shielded-v2-ingress-transparent"};
            }
            if (!RejectShieldedCanonicalFeeBucket(semantic_family,
                                                  payload.fee,
                                                  m_consensus,
                                                  m_validation_height,
                                                  proof_reject)) {
                return proof_reject;
            }

            auto context = shielded::v2::ParseV2IngressProof(*v2_bundle, proof_reject);
            if (!context.has_value()) {
                return proof_reject;
            }
            for (const auto& shard : context->witness.shards) {
                for (const auto& spend : shard.spends) {
                    if (!RejectShieldedMinimumPrivacyPool(spend.ring_positions.size(),
                                                          m_tree_snapshot->Size(),
                                                          m_consensus,
                                                          m_validation_height,
                                                          proof_reject)) {
                        return proof_reject;
                    }
                }
            }
            if (UseBridgeProofSystemAllowlist(m_consensus, m_validation_height) &&
                context->witness.header.settlement_witness.has_value() &&
                !RequireCanonicalBridgeProofSystems(
                    Span<const shielded::BridgeProofReceipt>{
                        context->witness.header.settlement_witness->proof_receipts.data(),
                        context->witness.header.settlement_witness->proof_receipts.size()},
                    Span<const shielded::BridgeProofAdapter>{},
                    proof_reject)) {
                return proof_reject;
            }

            if (context->backend.membership_proof_kind == shielded::v2::ProofComponentKind::SMILE_MEMBERSHIP) {
                if (!m_smile_public_accounts || !m_account_leaf_commitments) {
                    return std::string{"bad-shielded-ring-tree-unavailable"};
                }
                auto ring_members = shielded::v2::BuildV2IngressSmileRingMembers(*context,
                                                                                 *m_tree_snapshot,
                                                                                 *m_smile_public_accounts,
                                                                                 *m_account_leaf_commitments,
                                                                                 proof_reject);
                if (!ring_members.has_value()) {
                    return proof_reject;
                }
                if (!shielded::v2::VerifyV2IngressProof(*v2_bundle,
                                                        *context,
                                                        *ring_members,
                                                        proof_reject,
                                                        reject_rice_codec,
                                                        bind_smile_anonset_context)) {
                    return proof_reject;
                }
            } else {
                auto ring_members = shielded::v2::BuildV2IngressRingMembers(*context,
                                                                            *m_tree_snapshot,
                                                                            proof_reject);
                if (!ring_members.has_value()) {
                    return proof_reject;
                }
                if (!shielded::v2::VerifyV2IngressProof(*v2_bundle, *context, *ring_members, proof_reject)) {
                    return proof_reject;
                }
            }
            return std::nullopt;
        }
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
            if (payload.allow_transparent_unwrap || !m_tx->vin.empty() || !m_tx->vout.empty()) {
                return std::string{"bad-shielded-v2-egress-transparent-unwrap"};
            }

            std::string proof_reject;
            auto context = ParseV2EgressImportedReceiptContext(*v2_bundle, proof_reject);
            if (!context.has_value()) {
                return proof_reject;
            }
            auto witness = shielded::v2::proof::ParseSettlementWitness(v2_bundle->proof_payload, proof_reject);
            if (!witness.has_value()) {
                return proof_reject;
            }
            if (UseBridgeProofSystemAllowlist(m_consensus, m_validation_height) &&
                !RequireCanonicalBridgeProofSystems(
                    Span<const shielded::BridgeProofReceipt>{
                        witness->proof_receipts.data(),
                        witness->proof_receipts.size()},
                    Span<const shielded::BridgeProofAdapter>{
                        witness->imported_adapters.data(),
                        witness->imported_adapters.size()},
                    proof_reject)) {
                return proof_reject;
            }
            if (!shielded::v2::proof::VerifySettlementContext(*context, *witness, proof_reject)) {
                return proof_reject;
            }
            if (!VerifyV2EgressImportedReceiptBundle(*v2_bundle, *context, *witness, proof_reject)) {
                return proof_reject;
            }
            return std::nullopt;
        }
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR: {
            std::string proof_reject;
            if (UseBridgeProofSystemAllowlist(m_consensus, m_validation_height)) {
                auto witness = shielded::v2::proof::ParseSettlementWitness(v2_bundle->proof_payload, proof_reject);
                if (!witness.has_value()) {
                    return proof_reject;
                }
                if (!RequireCanonicalBridgeProofSystems(
                        Span<const shielded::BridgeProofReceipt>{
                            witness->proof_receipts.data(),
                            witness->proof_receipts.size()},
                        Span<const shielded::BridgeProofAdapter>{
                            witness->imported_adapters.data(),
                            witness->imported_adapters.size()},
                        proof_reject)) {
                    return proof_reject;
                }
            }
            auto settlement_anchors = ExtractCreatedShieldedSettlementAnchors(*m_tx, proof_reject);
            if (!settlement_anchors.has_value()) {
                return proof_reject;
            }
            if (settlement_anchors->empty()) {
                return std::string{"bad-shielded-v2-settlement-anchor"};
            }
            return std::nullopt;
        }
        case shielded::v2::TransactionFamily::V2_REBALANCE: {
            std::string proof_reject;
            auto manifest_states = ExtractCreatedShieldedNettingManifestStates(*m_tx,
                                                                              m_validation_height,
                                                                              proof_reject);
            if (!manifest_states.has_value()) {
                return proof_reject;
            }
            return std::nullopt;
        }
        case shielded::v2::TransactionFamily::V2_GENERIC:
            return std::string{"bad-shielded-v2-contextual"};
        default:
            return std::string{"bad-shielded-v2-contextual"};
        }
    }

    if (!bundle.HasShieldedInputs()) return std::nullopt;
    if (m_consensus != nullptr && m_consensus->IsShieldedMatRiCTDisabled(m_validation_height)) {
        return std::string{"bad-shielded-matrict-disabled"};
    }
    if (!m_tree_snapshot) return std::string{"bad-shielded-ring-tree-unavailable"};

    if (bundle.proof.empty()) return std::string{"bad-shielded-proof-missing"};
    if (bundle.proof.size() > MAX_SHIELDED_PROOF_BYTES) return std::string{"bad-shielded-proof-oversize"};

    std::string ring_member_error;
    auto ring_members = shielded::v2::proof::BuildLegacyDirectSpendRingMembers(bundle, *m_tree_snapshot, ring_member_error);
    if (!ring_members.has_value()) return ring_member_error;

    const shielded::v2::proof::ProofStatement statement =
        m_consensus != nullptr
            ? shielded::v2::proof::DescribeLegacyDirectSpendStatement(
                  *m_tx,
                  *m_consensus,
                  m_validation_height)
            : shielded::v2::proof::DescribeLegacyDirectSpendStatement(*m_tx);
    std::string proof_reject;
    std::optional<shielded::v2::proof::DirectSpendContext> context =
        m_parsed_proof
            ? std::optional<shielded::v2::proof::DirectSpendContext>{
                  shielded::v2::proof::BindLegacyDirectSpendProof(bundle, statement, m_parsed_proof)}
            : shielded::v2::proof::ParseLegacyDirectSpendProof(bundle, statement, proof_reject);
    if (!context.has_value()) return proof_reject;
    if (!context->IsValid(bundle.shielded_inputs.size())) return std::string{"bad-shielded-proof"};

    std::vector<uint256> output_note_commitments;
    output_note_commitments.reserve(bundle.shielded_outputs.size());
    std::transform(bundle.shielded_outputs.begin(),
                   bundle.shielded_outputs.end(),
                   std::back_inserter(output_note_commitments),
                   [](const CShieldedOutput& out) { return out.note_commitment; });
    std::vector<Nullifier> input_nullifiers;
    input_nullifiers.reserve(bundle.shielded_inputs.size());
    std::transform(bundle.shielded_inputs.begin(),
                   bundle.shielded_inputs.end(),
                   std::back_inserter(input_nullifiers),
                   [](const CShieldedInput& in) { return in.nullifier; });

    if (!shielded::v2::proof::VerifyLegacyDirectSpendProof(*context,
                                                           *ring_members,
                                                           input_nullifiers,
                                                           output_note_commitments,
                                                           bundle.value_balance)) {
        return std::string{"bad-shielded-proof"};
    }
    return std::nullopt;
}

void CShieldedProofCheck::swap(CShieldedProofCheck& other) noexcept
{
    std::swap(m_tx, other.m_tx);
    std::swap(m_consensus, other.m_consensus);
    std::swap(m_validation_height, other.m_validation_height);
    std::swap(m_tree_snapshot, other.m_tree_snapshot);
    std::swap(m_smile_public_accounts, other.m_smile_public_accounts);
    std::swap(m_account_leaf_commitments, other.m_account_leaf_commitments);
    std::swap(m_parsed_proof, other.m_parsed_proof);
}

CShieldedSpendAuthCheck::CShieldedSpendAuthCheck(const CTransaction& tx,
                                                 size_t spend_index,
                                                 std::optional<Nullifier> proof_bound_nullifier)
    : m_tx(MakeTransactionRef(tx)),
      m_spend_index(spend_index),
      m_proof_bound_nullifier(std::move(proof_bound_nullifier))
{
}

std::optional<std::string> CShieldedSpendAuthCheck::operator()() const
{
    if (!m_tx || m_tx->GetHash().IsNull()) return std::string{"bad-shielded-spend-auth-txid"};
    if (!m_tx->HasShieldedBundle()) return std::string{"bad-shielded-spend-auth-bundle"};

    const CShieldedBundle& bundle = m_tx->GetShieldedBundle();
    if (m_spend_index >= bundle.GetShieldedInputCount()) return std::string{"bad-shielded-spend-auth-index"};

    const Nullifier spend_nullifier = [&]() -> Nullifier {
        if (bundle.HasV2Bundle()) {
            const auto* v2_bundle = bundle.GetV2Bundle();
            if (v2_bundle == nullptr ||
                !shielded::v2::BundleHasSemanticFamily(*v2_bundle, shielded::v2::TransactionFamily::V2_SEND)) {
                return Nullifier{};
            }
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            return payload.spends[m_spend_index].nullifier;
        }
        return bundle.shielded_inputs[m_spend_index].nullifier;
    }();
    if (spend_nullifier.IsNull()) return std::string{"bad-shielded-spend-auth-nullifier"};

    if (m_proof_bound_nullifier.has_value() && *m_proof_bound_nullifier != spend_nullifier) {
        return std::string{"bad-shielded-spend-auth-nullifier-mismatch"};
    }

    if (!m_proof_bound_nullifier.has_value()) {
        std::string proof_reject;
        auto bound_nullifiers = ExtractShieldedProofBoundNullifiers(bundle, proof_reject);
        if (!bound_nullifiers.has_value()) return proof_reject;
        if (m_spend_index >= bound_nullifiers->size()) {
            return std::string{"bad-shielded-spend-auth-nullifier-count"};
        }
        if ((*bound_nullifiers)[m_spend_index] == spend_nullifier) return std::nullopt;
        return std::string{"bad-shielded-spend-auth-nullifier-mismatch"};
    }

    return std::nullopt;
}

void CShieldedSpendAuthCheck::swap(CShieldedSpendAuthCheck& other) noexcept
{
    std::swap(m_tx, other.m_tx);
    std::swap(m_spend_index, other.m_spend_index);
    std::swap(m_proof_bound_nullifier, other.m_proof_bound_nullifier);
}
