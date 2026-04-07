// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/bridge.h>

#include <addresstype.h>
#include <chainparams.h>
#include <hash.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>

namespace {

using shielded::BridgeDirection;
using shielded::BridgeBatchReceipt;
using shielded::BridgeBatchStatement;
using shielded::BridgeProofReceipt;
using shielded::BridgeProofClaim;
using shielded::BridgeProofClaimKind;
using shielded::BridgeProverSample;
using shielded::BridgeBatchAuthorization;
using shielded::BridgeBatchLeaf;
using shielded::BridgeBatchLeafKind;
using shielded::BridgeBatchCommitment;
using shielded::BridgeKeySpec;
using shielded::BridgeProofDescriptor;
using shielded::BridgeScriptTree;
using shielded::BridgeTemplateKind;
using BridgeKeyId = std::pair<uint8_t, std::vector<unsigned char>>;
using BridgeProofDescriptorId = std::pair<uint256, uint256>;

struct CanonicalBridgeProofAdapterTemplate
{
    std::string_view family;
    std::string_view proof_type;
    std::string_view claim_system;
    BridgeProofClaimKind claim_kind;
};

constexpr std::array<CanonicalBridgeProofAdapterTemplate, 14> CANONICAL_BRIDGE_PROOF_ADAPTERS{{
    {"sp1", "compressed", "settlement-metadata-v1", BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"sp1", "compressed", "batch-tuple-v1", BridgeProofClaimKind::BATCH_TUPLE},
    {"sp1", "plonk", "settlement-metadata-v1", BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"sp1", "plonk", "batch-tuple-v1", BridgeProofClaimKind::BATCH_TUPLE},
    {"sp1", "groth16", "settlement-metadata-v1", BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"sp1", "groth16", "batch-tuple-v1", BridgeProofClaimKind::BATCH_TUPLE},
    {"risc0-zkvm", "composite", "settlement-metadata-v1", BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"risc0-zkvm", "composite", "batch-tuple-v1", BridgeProofClaimKind::BATCH_TUPLE},
    {"risc0-zkvm", "succinct", "settlement-metadata-v1", BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"risc0-zkvm", "succinct", "batch-tuple-v1", BridgeProofClaimKind::BATCH_TUPLE},
    {"risc0-zkvm", "groth16", "settlement-metadata-v1", BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"risc0-zkvm", "groth16", "batch-tuple-v1", BridgeProofClaimKind::BATCH_TUPLE},
    {"blobstream", "sp1", "data-root-tuple-v1", BridgeProofClaimKind::DATA_ROOT_TUPLE},
    {"blobstream", "risc0", "data-root-tuple-v1", BridgeProofClaimKind::DATA_ROOT_TUPLE},
}};

[[nodiscard]] uint256 HashBridgeProofProfileLabelId(std::string_view label_domain,
                                                    std::string_view normalized_label)
{
    if (label_domain.empty() || normalized_label.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Profile_Label_V1"};
    hw << std::string{label_domain};
    hw << std::string{normalized_label};
    return hw.GetSHA256();
}

[[nodiscard]] std::optional<shielded::BridgeProofSystemProfile> BuildCanonicalBridgeProofSystemProfile(
    const CanonicalBridgeProofAdapterTemplate& adapter_template)
{
    shielded::BridgeProofSystemProfile profile;
    profile.family_id = HashBridgeProofProfileLabelId("family", adapter_template.family);
    profile.proof_type_id = HashBridgeProofProfileLabelId("proof_type", adapter_template.proof_type);
    profile.claim_system_id = HashBridgeProofProfileLabelId("claim_system", adapter_template.claim_system);
    if (!profile.IsValid()) return std::nullopt;
    return profile;
}

[[nodiscard]] bool IsValidKind(BridgeTemplateKind kind)
{
    return kind == BridgeTemplateKind::SHIELD || kind == BridgeTemplateKind::UNSHIELD;
}

[[nodiscard]] bool IsValidBatchLeafKindInternal(BridgeBatchLeafKind kind)
{
    return kind == BridgeBatchLeafKind::SHIELD_CREDIT ||
           kind == BridgeBatchLeafKind::TRANSPARENT_PAYOUT ||
           kind == BridgeBatchLeafKind::SHIELDED_PAYOUT;
}

[[nodiscard]] bool IsValidProofClaimKindInternal(BridgeProofClaimKind kind)
{
    return kind == BridgeProofClaimKind::BATCH_TUPLE ||
           kind == BridgeProofClaimKind::SETTLEMENT_METADATA ||
           kind == BridgeProofClaimKind::DATA_ROOT_TUPLE;
}

[[nodiscard]] bool IsValidAggregatePayloadLocationInternal(shielded::BridgeAggregatePayloadLocation location)
{
    using Location = shielded::BridgeAggregatePayloadLocation;
    return location == Location::INLINE_NON_WITNESS ||
           location == Location::INLINE_WITNESS ||
           location == Location::L1_DATA_AVAILABILITY ||
           location == Location::OFFCHAIN;
}

[[nodiscard]] bool IsValidDataArtifactKindInternal(shielded::BridgeDataArtifactKind kind)
{
    using Kind = shielded::BridgeDataArtifactKind;
    return kind == Kind::STATE_DIFF ||
           kind == Kind::SNAPSHOT_APPENDIX ||
           kind == Kind::DATA_ROOT_QUERY;
}

[[nodiscard]] size_t ExpectedBatchAuthorizationSignatureSize(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return MLDSA44_SIGNATURE_SIZE;
    case PQAlgorithm::SLH_DSA_128S:
        return SLHDSA128S_SIGNATURE_SIZE;
    }
    return 0;
}

[[nodiscard]] std::vector<unsigned char> MakeControlBlock(const uint256& sibling)
{
    std::vector<unsigned char> control;
    control.reserve(P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE);
    control.push_back(P2MR_LEAF_VERSION);
    control.insert(control.end(), sibling.begin(), sibling.end());
    return control;
}

[[nodiscard]] uint256 HashBridgeBatchNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeVerifierSetNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Verifier_Set_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeProofPolicyNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Policy_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeProofReceiptNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Receipt_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeProofArtifactNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Artifact_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeDataArtifactNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Data_Artifact_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeProverSampleNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Prover_Sample_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeProverProfileNode(const uint256& left, const uint256& right)
{
    if (left.IsNull() || right.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Prover_Profile_Node_V1"};
    hw << left;
    hw << right;
    return hw.GetSHA256();
}

[[nodiscard]] BridgeKeyId MakeBridgeKeyId(const BridgeKeySpec& key)
{
    return {static_cast<uint8_t>(key.algo), key.pubkey};
}

[[nodiscard]] BridgeProofDescriptorId MakeBridgeProofDescriptorId(const BridgeProofDescriptor& descriptor)
{
    return {descriptor.proof_system_id, descriptor.verifier_key_hash};
}

[[nodiscard]] std::optional<uint64_t> CheckedMultiplyU64(uint64_t lhs, uint64_t rhs)
{
    if (lhs == 0 || rhs == 0) return uint64_t{0};
    if (lhs > std::numeric_limits<uint64_t>::max() / rhs) return std::nullopt;
    return lhs * rhs;
}

[[nodiscard]] std::optional<uint64_t> CheckedAddU64(uint64_t lhs, uint64_t rhs)
{
    if (lhs > std::numeric_limits<uint64_t>::max() - rhs) return std::nullopt;
    return lhs + rhs;
}

[[nodiscard]] std::optional<uint64_t> CheckedDivideCeilU64(uint64_t numerator, uint64_t denominator)
{
    if (denominator == 0) return std::nullopt;
    const uint64_t quotient = numerator / denominator;
    if (numerator % denominator == 0) return quotient;
    if (quotient == std::numeric_limits<uint64_t>::max()) return std::nullopt;
    return quotient + 1;
}

[[nodiscard]] std::optional<shielded::BridgeProverLaneEstimate> EstimateBridgeProverLane(const shielded::BridgeProverLane& lane,
                                                                                          const shielded::BridgeCapacityEstimate& l1_capacity,
                                                                                          uint64_t block_interval_millis,
                                                                                          uint64_t l1_settlements_per_hour_limit,
                                                                                          uint64_t l1_users_per_hour_limit)
{
    if (!lane.IsValid() || block_interval_millis == 0) return std::nullopt;

    const auto effective_parallel_jobs = CheckedMultiplyU64(lane.workers, lane.parallel_jobs_per_worker);
    if (!effective_parallel_jobs.has_value()) return std::nullopt;

    const auto block_window_work = CheckedMultiplyU64(block_interval_millis, *effective_parallel_jobs);
    const auto hourly_work = CheckedMultiplyU64(3'600'000U, *effective_parallel_jobs);
    if (!block_window_work.has_value() || !hourly_work.has_value()) return std::nullopt;

    shielded::BridgeProverLaneEstimate estimate;
    estimate.lane = lane;
    estimate.effective_parallel_jobs = *effective_parallel_jobs;
    estimate.settlements_per_block_interval = *block_window_work / lane.millis_per_settlement;
    estimate.settlements_per_hour = *hourly_work / lane.millis_per_settlement;

    const auto users_per_block_interval = CheckedMultiplyU64(estimate.settlements_per_block_interval,
                                                             l1_capacity.footprint.batched_user_count);
    const auto users_per_hour = CheckedMultiplyU64(estimate.settlements_per_hour,
                                                   l1_capacity.footprint.batched_user_count);
    if (!users_per_block_interval.has_value() || !users_per_hour.has_value()) return std::nullopt;
    estimate.users_per_block_interval = *users_per_block_interval;
    estimate.users_per_hour = *users_per_hour;

    estimate.sustainable_settlements_per_block = std::min(estimate.settlements_per_block_interval,
                                                          l1_capacity.max_settlements_per_block);
    estimate.sustainable_settlements_per_hour = std::min(estimate.settlements_per_hour,
                                                         l1_settlements_per_hour_limit);
    estimate.sustainable_users_per_block = std::min(estimate.users_per_block_interval,
                                                    l1_capacity.users_per_block);
    estimate.sustainable_users_per_hour = std::min(estimate.users_per_hour,
                                                   l1_users_per_hour_limit);

    if (estimate.settlements_per_block_interval < l1_capacity.max_settlements_per_block) {
        estimate.binding_limit = shielded::BridgeThroughputBinding::PROVER;
    } else if (l1_capacity.max_settlements_per_block < estimate.settlements_per_block_interval) {
        estimate.binding_limit = shielded::BridgeThroughputBinding::L1;
    } else {
        estimate.binding_limit = shielded::BridgeThroughputBinding::TIED;
    }

    if (l1_capacity.max_settlements_per_block > 0) {
        const auto work_to_fill_l1 = CheckedMultiplyU64(l1_capacity.max_settlements_per_block,
                                                        lane.millis_per_settlement);
        if (!work_to_fill_l1.has_value()) return std::nullopt;

        const auto required_parallel_jobs = CheckedDivideCeilU64(*work_to_fill_l1, block_interval_millis);
        const auto required_workers = CheckedDivideCeilU64(*required_parallel_jobs, lane.parallel_jobs_per_worker);
        const auto millis_to_fill_l1_capacity = CheckedDivideCeilU64(*work_to_fill_l1, *effective_parallel_jobs);
        if (!required_parallel_jobs.has_value() ||
            !required_workers.has_value() ||
            !millis_to_fill_l1_capacity.has_value()) {
            return std::nullopt;
        }

        estimate.required_parallel_jobs_to_fill_l1_capacity = *required_parallel_jobs;
        estimate.required_workers_to_fill_l1_capacity = *required_workers;
        estimate.worker_gap_to_fill_l1_capacity = (*required_workers > lane.workers)
            ? *required_workers - lane.workers
            : 0;
        estimate.millis_to_fill_l1_capacity = *millis_to_fill_l1_capacity;
    }

    const auto current_hourly_cost_cents = CheckedMultiplyU64(lane.hourly_cost_cents, lane.workers);
    const auto required_hourly_cost_cents = CheckedMultiplyU64(lane.hourly_cost_cents,
                                                               estimate.required_workers_to_fill_l1_capacity);
    if (!current_hourly_cost_cents.has_value() || !required_hourly_cost_cents.has_value()) return std::nullopt;
    estimate.current_hourly_cost_cents = *current_hourly_cost_cents;
    estimate.required_hourly_cost_cents = *required_hourly_cost_cents;
    return estimate;
}

[[nodiscard]] std::optional<BridgeScriptTree> BuildBridgeTreeCommon(BridgeTemplateKind kind,
                                                                    const BridgeKeySpec& normal_key,
                                                                    uint32_t refund_lock_height,
                                                                    const BridgeKeySpec& refund_key,
                                                                    std::vector<unsigned char> normal_leaf_script)
{
    if (!IsValidKind(kind) || !normal_key.IsValid() || !refund_key.IsValid() || !shielded::IsValidRefundLockHeight(refund_lock_height)) {
        return std::nullopt;
    }

    std::vector<unsigned char> refund_leaf_script = BuildP2MRRefundLeaf(refund_lock_height, refund_key.algo, refund_key.pubkey);
    if (normal_leaf_script.empty() || refund_leaf_script.empty()) {
        return std::nullopt;
    }

    BridgeScriptTree tree;
    tree.kind = kind;
    tree.normal_key = normal_key;
    tree.refund_key = refund_key;
    tree.refund_lock_height = refund_lock_height;
    tree.normal_leaf_script = std::move(normal_leaf_script);
    tree.refund_leaf_script = std::move(refund_leaf_script);
    tree.normal_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, tree.normal_leaf_script);
    tree.refund_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, tree.refund_leaf_script);
    if (tree.normal_leaf_hash.IsNull() || tree.refund_leaf_hash.IsNull() || tree.normal_leaf_hash == tree.refund_leaf_hash) {
        return std::nullopt;
    }

    tree.merkle_root = ComputeP2MRMerkleRoot({tree.normal_leaf_hash, tree.refund_leaf_hash});
    if (tree.merkle_root.IsNull()) return std::nullopt;

    tree.normal_control_block = MakeControlBlock(tree.refund_leaf_hash);
    tree.refund_control_block = MakeControlBlock(tree.normal_leaf_hash);
    if (!tree.IsValid()) return std::nullopt;
    return tree;
}

} // namespace

namespace shielded {

bool BridgeKeySpec::IsValid() const
{
    return IsValidBridgePubkey(algo, pubkey);
}

bool BridgePlanIds::IsValid() const
{
    return !bridge_id.IsNull() && !operation_id.IsNull();
}

bool BridgeBatchLeaf::IsValid() const
{
    return IsValidBatchLeafKindInternal(kind) &&
           !wallet_id.IsNull() &&
           !destination_id.IsNull() &&
           MoneyRange(amount) &&
           amount > 0 &&
           !authorization_hash.IsNull();
}

bool BridgeExternalAnchor::IsEmpty() const
{
    return domain_id.IsNull() &&
           source_epoch == 0 &&
           data_root.IsNull() &&
           verification_root.IsNull();
}

bool BridgeExternalAnchor::IsValid() const
{
    return version == 1 &&
           !domain_id.IsNull() &&
           source_epoch > 0 &&
           (!data_root.IsNull() || !verification_root.IsNull());
}

bool BridgeVerifierSetCommitment::IsEmpty() const
{
    return attestor_count == 0 &&
           required_signers == 0 &&
           attestor_root.IsNull();
}

bool BridgeVerifierSetCommitment::IsValid() const
{
    return version == 1 &&
           attestor_count > 0 &&
           required_signers > 0 &&
           required_signers <= attestor_count &&
           !attestor_root.IsNull();
}

bool BridgeVerifierSetProof::IsValid() const
{
    return version == 1;
}

bool BridgeProofSystemProfile::IsValid() const
{
    return version == 1 &&
           !family_id.IsNull() &&
           !proof_type_id.IsNull() &&
           !claim_system_id.IsNull();
}

bool BridgeProofClaim::IsValid() const
{
    if (version != 1 || statement_hash.IsNull() || !IsValidProofClaimKindInternal(kind)) return false;

    const bool has_batch_tuple = ids.IsValid() &&
                                 entry_count > 0 &&
                                 MoneyRange(total_amount) &&
                                 total_amount > 0 &&
                                 !batch_root.IsNull() &&
                                 (direction == BridgeDirection::BRIDGE_IN || direction == BridgeDirection::BRIDGE_OUT);
    const bool has_data_root_tuple = !domain_id.IsNull() &&
                                     source_epoch > 0 &&
                                     !data_root.IsNull();
    const bool empty_batch_tuple = !ids.IsValid() &&
                                   entry_count == 0 &&
                                   total_amount == 0 &&
                                   batch_root.IsNull();
    const bool empty_data_root_tuple = domain_id.IsNull() &&
                                       source_epoch == 0 &&
                                       data_root.IsNull();

    if (kind == BridgeProofClaimKind::BATCH_TUPLE) {
        return has_batch_tuple && empty_data_root_tuple;
    }
    if (kind == BridgeProofClaimKind::SETTLEMENT_METADATA) {
        return has_batch_tuple && has_data_root_tuple;
    }
    if (kind == BridgeProofClaimKind::DATA_ROOT_TUPLE) {
        return empty_batch_tuple && has_data_root_tuple;
    }
    return false;
}

bool BridgeProofAdapter::IsValid() const
{
    return version == 1 &&
           profile.IsValid() &&
           IsValidProofClaimKindInternal(claim_kind);
}

bool BridgeProofArtifact::IsValid() const
{
    return version == 1 &&
           adapter.IsValid() &&
           !statement_hash.IsNull() &&
           !verifier_key_hash.IsNull() &&
           !public_values_hash.IsNull() &&
           !proof_commitment.IsNull() &&
           !artifact_commitment.IsNull() &&
           proof_size_bytes > 0 &&
           public_values_size_bytes > 0;
}

bool BridgeDataArtifact::IsValid() const
{
    return version == 1 &&
           IsValidDataArtifactKindInternal(kind) &&
           !statement_hash.IsNull() &&
           !data_root.IsNull() &&
           !payload_commitment.IsNull() &&
           !artifact_commitment.IsNull() &&
           payload_size_bytes > 0;
}

bool BridgeAggregateArtifactBundle::IsValid() const
{
    if (version != 1 || statement_hash.IsNull()) return false;

    const bool has_proof_artifacts = proof_artifact_count > 0;
    const bool has_data_artifacts = data_artifact_count > 0;
    if (!has_proof_artifacts && !has_data_artifacts) return false;

    if (has_proof_artifacts) {
        if (proof_artifact_root.IsNull() || proof_payload_bytes == 0) return false;
    } else if (!proof_artifact_root.IsNull() || proof_payload_bytes != 0 || proof_auxiliary_bytes != 0) {
        return false;
    }

    if (has_data_artifacts) {
        if (data_artifact_root.IsNull() || data_availability_payload_bytes == 0) return false;
    } else if (!data_artifact_root.IsNull() || data_availability_payload_bytes != 0 || data_auxiliary_bytes != 0) {
        return false;
    }

    return true;
}

bool BridgeAggregateSettlement::IsValid() const
{
    return version == 1 &&
           !statement_hash.IsNull() &&
           batched_user_count > 0 &&
           new_wallet_count <= batched_user_count &&
           (input_count > 0 || output_count > 0) &&
           base_non_witness_bytes > 0 &&
           state_commitment_bytes > 0 &&
           IsValidAggregatePayloadLocationInternal(proof_payload_location) &&
           IsValidAggregatePayloadLocationInternal(data_availability_location);
}

bool BridgeCapacityFootprint::IsValid() const
{
    return l1_serialized_bytes > 0 &&
           l1_weight > 0 &&
           batched_user_count > 0;
}

bool BridgeProofCompressionTarget::IsValid() const
{
    if (version != 1 ||
        settlement_id.IsNull() ||
        statement_hash.IsNull() ||
        block_serialized_limit == 0 ||
        block_weight_limit == 0 ||
        target_users_per_block == 0 ||
        target_settlements_per_block == 0 ||
        batched_user_count == 0 ||
        !IsValidAggregatePayloadLocationInternal(proof_payload_location)) {
        return false;
    }

    const auto represented_users = CheckedMultiplyU64(target_settlements_per_block,
                                                      static_cast<uint64_t>(batched_user_count));
    if (!represented_users.has_value() || target_users_per_block > *represented_users) return false;
    if (target_settlements_per_block > 1) {
        const auto previous_represented_users = CheckedMultiplyU64(target_settlements_per_block - 1,
                                                                   static_cast<uint64_t>(batched_user_count));
        if (!previous_represented_users.has_value()) return false;
        if (target_users_per_block <= *previous_represented_users) return false;
    }

    if (proof_artifact_count == 0 && current_proof_auxiliary_bytes != 0) return false;
    if ((fixed_l1_data_availability_bytes > 0 ||
         proof_payload_location == BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY) &&
        block_data_availability_limit == 0) {
        return false;
    }

    return true;
}

bool BridgeShieldedStateProfile::IsValid() const
{
    return version == 1 &&
           commitment_index_key_bytes > 0 &&
           commitment_index_value_bytes > 0 &&
           snapshot_commitment_bytes > 0 &&
           nullifier_index_key_bytes > 0 &&
           nullifier_index_value_bytes > 0 &&
           snapshot_nullifier_bytes > 0 &&
           nullifier_cache_bytes > 0;
}

bool BridgeShieldedStateRetentionPolicy::IsValid() const
{
    return version == 1 &&
           wallet_l1_materialization_bps <= 10'000 &&
           snapshot_target_bytes > 0;
}

bool BridgeProverLane::IsValid() const
{
    return millis_per_settlement > 0 &&
           workers > 0 &&
           parallel_jobs_per_worker > 0;
}

bool BridgeProverFootprint::IsValid() const
{
    if (block_interval_millis == 0) return false;

    size_t lane_count = 0;
    for (const auto* lane : {&native, &cpu, &gpu, &network}) {
        if (!lane->has_value()) continue;
        if (!lane->value().IsValid()) return false;
        ++lane_count;
    }
    return lane_count > 0;
}

bool BridgeProverSample::IsValid() const
{
    return version == 1 &&
           !statement_hash.IsNull() &&
           !proof_artifact_id.IsNull() &&
           !proof_system_id.IsNull() &&
           !verifier_key_hash.IsNull() &&
           artifact_storage_bytes > 0 &&
           (native_millis > 0 || cpu_millis > 0 || gpu_millis > 0 || network_millis > 0);
}

bool BridgeProverProfile::IsValid() const
{
    return version == 1 &&
           !statement_hash.IsNull() &&
           sample_count > 0 &&
           !sample_root.IsNull() &&
           total_artifact_storage_bytes > 0 &&
           (native_millis_per_settlement > 0 ||
            cpu_millis_per_settlement > 0 ||
            gpu_millis_per_settlement > 0 ||
            network_millis_per_settlement > 0);
}

bool BridgeProverMetricSummary::IsValid() const
{
    return min <= p50 &&
           p50 <= p90 &&
           p90 <= max;
}

bool BridgeProverBenchmark::IsValid() const
{
    return version == 1 &&
           !statement_hash.IsNull() &&
           profile_count > 0 &&
           sample_count_per_profile > 0 &&
           !profile_root.IsNull() &&
           artifact_storage_bytes_per_profile > 0 &&
           total_peak_memory_bytes.IsValid() &&
           max_peak_memory_bytes.IsValid() &&
           native_millis_per_settlement.IsValid() &&
           cpu_millis_per_settlement.IsValid() &&
           gpu_millis_per_settlement.IsValid() &&
           network_millis_per_settlement.IsValid() &&
           (native_millis_per_settlement.max > 0 ||
            cpu_millis_per_settlement.max > 0 ||
            gpu_millis_per_settlement.max > 0 ||
            network_millis_per_settlement.max > 0);
}

bool BridgeProofDescriptor::IsValid() const
{
    return !proof_system_id.IsNull() && !verifier_key_hash.IsNull();
}

bool BridgeProofPolicyCommitment::IsEmpty() const
{
    return descriptor_count == 0 &&
           required_receipts == 0 &&
           descriptor_root.IsNull();
}

bool BridgeProofPolicyCommitment::IsValid() const
{
    return version == 1 &&
           descriptor_count > 0 &&
           required_receipts > 0 &&
           !descriptor_root.IsNull();
}

bool BridgeProofPolicyProof::IsValid() const
{
    return version == 1;
}

bool BridgeVerificationBundle::IsValid() const
{
    return version == 1 &&
           !signed_receipt_root.IsNull() &&
           !proof_receipt_root.IsNull();
}

bool BridgeBatchAggregateCommitment::IsEmpty() const
{
    return action_root.IsNull() &&
           data_availability_root.IsNull() &&
           recovery_or_exit_root.IsNull() &&
           extension_flags == 0 &&
           policy_commitment.IsNull();
}

bool BridgeBatchAggregateCommitment::IsValid() const
{
    if (version != 1 || action_root.IsNull() || data_availability_root.IsNull()) return false;

    const bool has_recovery_root = !recovery_or_exit_root.IsNull();
    const bool flagged_recovery_root = (extension_flags & FLAG_HAS_RECOVERY_OR_EXIT_ROOT) != 0;
    if (has_recovery_root != flagged_recovery_root) return false;

    const bool has_policy = !policy_commitment.IsNull();
    const bool flagged_policy = (extension_flags & FLAG_HAS_POLICY_COMMITMENT) != 0;
    if (has_policy != flagged_policy) return false;

    return true;
}

bool BridgeBatchStatement::IsValid() const
{
    const bool has_common_fields = !batch_root.IsNull() &&
                                   !domain_id.IsNull() &&
                                   !data_root.IsNull() &&
                                   ids.IsValid() &&
                                   entry_count > 0 &&
                                   source_epoch > 0 &&
                                   MoneyRange(total_amount) &&
                                   total_amount > 0 &&
                                   (direction == BridgeDirection::BRIDGE_IN || direction == BridgeDirection::BRIDGE_OUT);
    if (!has_common_fields) return false;
    if (version == 1) return verifier_set.IsEmpty() && proof_policy.IsEmpty();
    if (version == 2) return verifier_set.IsValid() && proof_policy.IsEmpty();
    if (version == 3) return verifier_set.IsEmpty() && proof_policy.IsValid();
    if (version == 4) return verifier_set.IsValid() && proof_policy.IsValid();
    if (version == 5) {
        return (verifier_set.IsEmpty() || verifier_set.IsValid()) &&
               (proof_policy.IsEmpty() || proof_policy.IsValid()) &&
               aggregate_commitment.IsValid();
    }
    return false;
}

bool BridgeBatchCommitment::IsValid() const
{
    const bool has_common_fields = !batch_root.IsNull() &&
                                   ids.IsValid() &&
                                   entry_count > 0 &&
                                   MoneyRange(total_amount) &&
                                   total_amount > 0 &&
                                   (direction == BridgeDirection::BRIDGE_IN || direction == BridgeDirection::BRIDGE_OUT);
    if (!has_common_fields) return false;
    if (version == 1) return external_anchor.IsEmpty();
    if (version == 2) return external_anchor.IsValid();
    if (version == 3) return (external_anchor.IsEmpty() || external_anchor.IsValid()) &&
                              aggregate_commitment.IsValid();
    return false;
}

bool BridgeBatchReceipt::IsMessageValid() const
{
    return version == 1 &&
           statement.IsValid() &&
           attestor.IsValid();
}

bool BridgeBatchReceipt::HasSignature() const
{
    return !signature.empty() && signature.size() == ExpectedBatchAuthorizationSignatureSize(attestor.algo);
}

bool BridgeBatchReceipt::IsValid() const
{
    return VerifyBridgeBatchReceipt(*this);
}

bool BridgeProofReceipt::IsValid() const
{
    return version == 1 &&
           !statement_hash.IsNull() &&
           !proof_system_id.IsNull() &&
           !verifier_key_hash.IsNull() &&
           !public_values_hash.IsNull() &&
           !proof_commitment.IsNull();
}

bool BridgeBatchAuthorization::IsMessageValid() const
{
    return version == 1 &&
           ids.IsValid() &&
           (direction == BridgeDirection::BRIDGE_IN || direction == BridgeDirection::BRIDGE_OUT) &&
           IsValidBatchLeafKindInternal(kind) &&
           !wallet_id.IsNull() &&
           !destination_id.IsNull() &&
           MoneyRange(amount) &&
           amount > 0 &&
           !authorization_nonce.IsNull() &&
           authorizer.IsValid();
}

bool BridgeBatchAuthorization::HasSignature() const
{
    return !signature.empty() && signature.size() == ExpectedBatchAuthorizationSignatureSize(authorizer.algo);
}

bool BridgeBatchAuthorization::IsValid() const
{
    return VerifyBridgeBatchAuthorization(*this);
}

bool BridgeScriptTree::IsValid() const
{
    if (!IsValidKind(kind) || !normal_key.IsValid() || !refund_key.IsValid()) return false;
    if (!IsValidRefundLockHeight(refund_lock_height)) return false;
    if (merkle_root.IsNull() || normal_leaf_hash.IsNull() || refund_leaf_hash.IsNull()) return false;
    if (normal_leaf_hash == refund_leaf_hash) return false;
    if (normal_leaf_script.empty() || refund_leaf_script.empty()) return false;
    if (normal_control_block.size() != P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE) return false;
    if (refund_control_block.size() != P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE) return false;
    const Span<const unsigned char> program{merkle_root.begin(), merkle_root.size()};
    return VerifyP2MRCommitment(normal_control_block, program, normal_leaf_hash) &&
           VerifyP2MRCommitment(refund_control_block, program, refund_leaf_hash);
}

bool IsValidBridgePubkey(PQAlgorithm algo, Span<const unsigned char> pubkey)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return pubkey.size() == MLDSA44_PUBKEY_SIZE;
    case PQAlgorithm::SLH_DSA_128S:
        return pubkey.size() == SLHDSA128S_PUBKEY_SIZE;
    }
    return false;
}

uint256 ComputeBridgeVerifierSetLeafHash(const BridgeKeySpec& attestor)
{
    if (!attestor.IsValid()) return uint256{};
    DataStream ds{};
    ds << attestor;
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Verifier_Set_Leaf_V1"};
    hw.write(MakeByteSpan(ds));
    return hw.GetSHA256();
}

uint256 ComputeBridgeVerifierSetRoot(Span<const BridgeKeySpec> attestors)
{
    if (attestors.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(attestors.size());
    for (const auto& attestor : attestors) {
        const uint256 leaf_hash = ComputeBridgeVerifierSetLeafHash(attestor);
        if (leaf_hash.IsNull()) return uint256{};
        level.push_back(leaf_hash);
    }
    std::sort(level.begin(), level.end());

    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeVerifierSetNode(left, right);
            if (parent.IsNull()) return uint256{};
            next.push_back(parent);
        }
        level = std::move(next);
    }
    return level.front();
}

std::optional<BridgeVerifierSetCommitment> BuildBridgeVerifierSetCommitment(Span<const BridgeKeySpec> attestors,
                                                                            size_t required_signers)
{
    if (attestors.empty() || required_signers == 0 || required_signers > attestors.size()) return std::nullopt;

    std::set<BridgeKeyId> unique_attestors;
    for (const auto& attestor : attestors) {
        if (!attestor.IsValid()) return std::nullopt;
        if (!unique_attestors.emplace(MakeBridgeKeyId(attestor)).second) return std::nullopt;
    }

    BridgeVerifierSetCommitment verifier_set;
    verifier_set.attestor_count = static_cast<uint32_t>(attestors.size());
    verifier_set.required_signers = static_cast<uint32_t>(required_signers);
    verifier_set.attestor_root = ComputeBridgeVerifierSetRoot(attestors);
    if (!verifier_set.IsValid()) return std::nullopt;
    return verifier_set;
}

std::vector<uint8_t> SerializeBridgeVerifierSetProof(const BridgeVerifierSetProof& proof)
{
    if (!proof.IsValid()) return {};
    DataStream ds{};
    ds << proof;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeVerifierSetProof> DeserializeBridgeVerifierSetProof(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeVerifierSetProof proof;
    ds >> proof;
    if (!ds.empty() || !proof.IsValid()) return std::nullopt;
    return proof;
}

std::optional<BridgeVerifierSetProof> BuildBridgeVerifierSetProof(Span<const BridgeKeySpec> attestors,
                                                                  const BridgeKeySpec& attestor)
{
    if (!attestor.IsValid() || attestors.empty()) return std::nullopt;

    std::set<BridgeKeyId> unique_attestors;
    std::vector<std::pair<uint256, BridgeKeyId>> leaves;
    leaves.reserve(attestors.size());
    for (const auto& candidate : attestors) {
        if (!candidate.IsValid()) return std::nullopt;
        const BridgeKeyId candidate_id = MakeBridgeKeyId(candidate);
        if (!unique_attestors.emplace(candidate_id).second) return std::nullopt;
        const uint256 leaf_hash = ComputeBridgeVerifierSetLeafHash(candidate);
        if (leaf_hash.IsNull()) return std::nullopt;
        leaves.emplace_back(leaf_hash, candidate_id);
    }
    std::sort(leaves.begin(), leaves.end(), [](const auto& a, const auto& b) {
        if (a.first == b.first) return a.second < b.second;
        return a.first < b.first;
    });

    const BridgeKeyId target_id = MakeBridgeKeyId(attestor);
    const uint256 target_hash = ComputeBridgeVerifierSetLeafHash(attestor);
    if (target_hash.IsNull()) return std::nullopt;

    size_t index{0};
    bool found{false};
    for (; index < leaves.size(); ++index) {
        if (leaves[index].first == target_hash && leaves[index].second == target_id) {
            found = true;
            break;
        }
    }
    if (!found) return std::nullopt;

    BridgeVerifierSetProof proof;
    proof.leaf_index = static_cast<uint32_t>(index);

    std::vector<uint256> level;
    level.reserve(leaves.size());
    for (const auto& leaf : leaves) {
        level.push_back(leaf.first);
    }

    while (level.size() > 1) {
        const size_t sibling_index = (index % 2 == 0)
            ? ((index + 1 < level.size()) ? index + 1 : index)
            : index - 1;
        proof.siblings.push_back(level[sibling_index]);

        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeVerifierSetNode(left, right);
            if (parent.IsNull()) return std::nullopt;
            next.push_back(parent);
        }
        level = std::move(next);
        index /= 2;
    }

    if (!proof.IsValid()) return std::nullopt;
    return proof;
}

bool VerifyBridgeVerifierSetProof(const BridgeVerifierSetCommitment& verifier_set,
                                  const BridgeKeySpec& attestor,
                                  const BridgeVerifierSetProof& proof)
{
    if (!verifier_set.IsValid() || !attestor.IsValid() || !proof.IsValid()) return false;
    if (proof.leaf_index >= verifier_set.attestor_count) return false;

    uint32_t expected_depth{0};
    for (uint32_t width = verifier_set.attestor_count; width > 1; width = (width + 1) / 2) {
        ++expected_depth;
    }
    if (proof.siblings.size() != expected_depth) return false;

    uint256 hash = ComputeBridgeVerifierSetLeafHash(attestor);
    if (hash.IsNull()) return false;

    uint32_t index = proof.leaf_index;
    uint32_t width = verifier_set.attestor_count;
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
        const uint256& sibling = proof.siblings[i];
        if (sibling.IsNull()) return false;

        if ((index % 2) == 0) {
            const bool has_distinct_right = index + 1 < width;
            if (!has_distinct_right && sibling != hash) return false;
            hash = HashBridgeVerifierSetNode(hash, has_distinct_right ? sibling : hash);
        } else {
            hash = HashBridgeVerifierSetNode(sibling, hash);
        }
        if (hash.IsNull()) return false;

        index /= 2;
        width = (width + 1) / 2;
    }

    return hash == verifier_set.attestor_root;
}

std::vector<uint8_t> SerializeBridgeProofSystemProfile(const BridgeProofSystemProfile& profile)
{
    if (!profile.IsValid()) return {};
    DataStream ds{};
    ds << profile;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeProofSystemProfile> DeserializeBridgeProofSystemProfile(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProofSystemProfile profile;
    try {
        ds >> profile;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !profile.IsValid()) return std::nullopt;
    return profile;
}

uint256 ComputeBridgeProofSystemId(const BridgeProofSystemProfile& profile)
{
    const auto bytes = SerializeBridgeProofSystemProfile(profile);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_System_Profile_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::vector<uint8_t> SerializeBridgeProofClaim(const BridgeProofClaim& claim)
{
    if (!claim.IsValid()) return {};
    DataStream ds{};
    ds << claim;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeProofClaim> DeserializeBridgeProofClaim(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProofClaim claim;
    try {
        ds >> claim;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !claim.IsValid()) return std::nullopt;
    return claim;
}

uint256 ComputeBridgeProofClaimHash(const BridgeProofClaim& claim)
{
    const auto bytes = SerializeBridgeProofClaim(claim);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Claim_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::optional<BridgeProofClaim> BuildBridgeProofClaimFromStatement(const BridgeBatchStatement& statement,
                                                                   BridgeProofClaimKind kind)
{
    if (!statement.IsValid() || !IsValidProofClaimKindInternal(kind)) return std::nullopt;

    BridgeProofClaim claim;
    claim.kind = kind;
    claim.statement_hash = ComputeBridgeBatchStatementHash(statement);
    if (claim.statement_hash.IsNull()) return std::nullopt;

    if (kind == BridgeProofClaimKind::BATCH_TUPLE || kind == BridgeProofClaimKind::SETTLEMENT_METADATA) {
        claim.direction = statement.direction;
        claim.ids = statement.ids;
        claim.entry_count = statement.entry_count;
        claim.total_amount = statement.total_amount;
        claim.batch_root = statement.batch_root;
    }

    if (kind == BridgeProofClaimKind::SETTLEMENT_METADATA || kind == BridgeProofClaimKind::DATA_ROOT_TUPLE) {
        claim.domain_id = statement.domain_id;
        claim.source_epoch = statement.source_epoch;
        claim.data_root = statement.data_root;
    }

    if (!claim.IsValid()) return std::nullopt;
    return claim;
}

bool DoesBridgeProofClaimMatchStatement(const BridgeProofClaim& claim, const BridgeBatchStatement& statement)
{
    if (!claim.IsValid() || !statement.IsValid()) return false;
    const auto expected = BuildBridgeProofClaimFromStatement(statement, claim.kind);
    if (!expected.has_value()) return false;
    return SerializeBridgeProofClaim(*expected) == SerializeBridgeProofClaim(claim);
}

std::vector<uint8_t> SerializeBridgeProofAdapter(const BridgeProofAdapter& adapter)
{
    if (!adapter.IsValid()) return {};
    DataStream ds{};
    ds << adapter;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeProofAdapter> DeserializeBridgeProofAdapter(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProofAdapter adapter;
    try {
        ds >> adapter;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !adapter.IsValid()) return std::nullopt;
    return adapter;
}

uint256 ComputeBridgeProofAdapterId(const BridgeProofAdapter& adapter)
{
    const auto bytes = SerializeBridgeProofAdapter(adapter);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Adapter_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

uint256 ComputeBridgeProofArtifactCommitment(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Artifact_Bundle_V1"};
    hw.write(AsBytes(bytes));
    return hw.GetSHA256();
}

std::optional<BridgeProofClaim> BuildBridgeProofClaimFromAdapter(const BridgeBatchStatement& statement,
                                                                 const BridgeProofAdapter& adapter)
{
    if (!adapter.IsValid()) return std::nullopt;
    return BuildBridgeProofClaimFromStatement(statement, adapter.claim_kind);
}

std::vector<uint8_t> SerializeBridgeProofArtifact(const BridgeProofArtifact& artifact)
{
    if (!artifact.IsValid()) return {};
    DataStream ds{};
    ds << artifact;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeProofArtifact> DeserializeBridgeProofArtifact(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProofArtifact artifact;
    try {
        ds >> artifact;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !artifact.IsValid()) return std::nullopt;
    return artifact;
}

uint256 ComputeBridgeProofArtifactId(const BridgeProofArtifact& artifact)
{
    const auto bytes = SerializeBridgeProofArtifact(artifact);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Artifact_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

uint64_t GetBridgeProofArtifactStorageBytes(const BridgeProofArtifact& artifact)
{
    if (!artifact.IsValid()) return 0;
    return static_cast<uint64_t>(artifact.proof_size_bytes) +
           static_cast<uint64_t>(artifact.public_values_size_bytes) +
           static_cast<uint64_t>(artifact.auxiliary_data_size_bytes);
}

namespace {
[[nodiscard]] uint256 ComputeBridgeProofArtifactLeafHash(const BridgeProofArtifact& artifact)
{
    if (!artifact.IsValid()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Artifact_Leaf_V1"};
    hw << artifact;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeBridgeProofArtifactRoot(Span<const BridgeProofArtifact> artifacts)
{
    if (artifacts.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(artifacts.size());
    for (const auto& artifact : artifacts) {
        const uint256 leaf_hash = ComputeBridgeProofArtifactLeafHash(artifact);
        if (leaf_hash.IsNull()) return uint256{};
        level.push_back(leaf_hash);
    }
    std::sort(level.begin(), level.end());

    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 node = HashBridgeProofArtifactNode(left, right);
            if (node.IsNull()) return uint256{};
            next.push_back(node);
        }
        level = std::move(next);
    }
    return level.front();
}

[[nodiscard]] uint256 ComputeBridgeDataArtifactLeafHash(const BridgeDataArtifact& artifact)
{
    if (!artifact.IsValid()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Data_Artifact_Leaf_V1"};
    hw << artifact;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeBridgeDataArtifactRoot(Span<const BridgeDataArtifact> artifacts)
{
    if (artifacts.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(artifacts.size());
    for (const auto& artifact : artifacts) {
        const uint256 leaf_hash = ComputeBridgeDataArtifactLeafHash(artifact);
        if (leaf_hash.IsNull()) return uint256{};
        level.push_back(leaf_hash);
    }
    std::sort(level.begin(), level.end());

    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 node = HashBridgeDataArtifactNode(left, right);
            if (node.IsNull()) return uint256{};
            next.push_back(node);
        }
        level = std::move(next);
    }
    return level.front();
}

[[nodiscard]] std::optional<uint64_t> ComputeProofPayloadWeightBytes(uint64_t proof_payload_bytes,
                                                                     shielded::BridgeAggregatePayloadLocation location)
{
    switch (location) {
    case shielded::BridgeAggregatePayloadLocation::INLINE_NON_WITNESS:
        return CheckedMultiplyU64(proof_payload_bytes, 4);
    case shielded::BridgeAggregatePayloadLocation::INLINE_WITNESS:
        return proof_payload_bytes;
    case shielded::BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY:
    case shielded::BridgeAggregatePayloadLocation::OFFCHAIN:
        return 0;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<shielded::BridgeCapacityFootprint> BuildBridgeProofCompressionFootprint(
    const shielded::BridgeProofCompressionTarget& target,
    uint64_t proof_payload_bytes)
{
    if (!target.IsValid()) return std::nullopt;

    uint64_t l1_serialized_bytes = target.fixed_l1_serialized_bytes;
    uint64_t l1_weight = target.fixed_l1_weight;
    uint64_t l1_data_availability_bytes = target.fixed_l1_data_availability_bytes;
    uint64_t offchain_storage_bytes = target.fixed_offchain_storage_bytes;

    switch (target.proof_payload_location) {
    case shielded::BridgeAggregatePayloadLocation::INLINE_NON_WITNESS: {
        const auto serialized_total = CheckedAddU64(l1_serialized_bytes, proof_payload_bytes);
        const auto proof_weight = ComputeProofPayloadWeightBytes(proof_payload_bytes, target.proof_payload_location);
        if (!serialized_total.has_value() || !proof_weight.has_value()) return std::nullopt;
        const auto weight_total = CheckedAddU64(l1_weight, *proof_weight);
        if (!weight_total.has_value()) return std::nullopt;
        l1_serialized_bytes = *serialized_total;
        l1_weight = *weight_total;
        break;
    }
    case shielded::BridgeAggregatePayloadLocation::INLINE_WITNESS: {
        const auto serialized_total = CheckedAddU64(l1_serialized_bytes, proof_payload_bytes);
        const auto proof_weight = ComputeProofPayloadWeightBytes(proof_payload_bytes, target.proof_payload_location);
        if (!serialized_total.has_value() || !proof_weight.has_value()) return std::nullopt;
        const auto weight_total = CheckedAddU64(l1_weight, *proof_weight);
        if (!weight_total.has_value()) return std::nullopt;
        l1_serialized_bytes = *serialized_total;
        l1_weight = *weight_total;
        break;
    }
    case shielded::BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY: {
        const auto data_total = CheckedAddU64(l1_data_availability_bytes, proof_payload_bytes);
        if (!data_total.has_value()) return std::nullopt;
        l1_data_availability_bytes = *data_total;
        break;
    }
    case shielded::BridgeAggregatePayloadLocation::OFFCHAIN: {
        const auto offchain_total = CheckedAddU64(offchain_storage_bytes, proof_payload_bytes);
        if (!offchain_total.has_value()) return std::nullopt;
        offchain_storage_bytes = *offchain_total;
        break;
    }
    }

    shielded::BridgeCapacityFootprint footprint;
    footprint.l1_serialized_bytes = l1_serialized_bytes;
    footprint.l1_weight = l1_weight;
    footprint.l1_data_availability_bytes = l1_data_availability_bytes;
    footprint.control_plane_bytes = target.fixed_control_plane_bytes;
    footprint.offchain_storage_bytes = offchain_storage_bytes;
    footprint.batched_user_count = target.batched_user_count;
    if (!footprint.IsValid()) return std::nullopt;
    return footprint;
}

[[nodiscard]] std::optional<uint64_t> ComputeMaxProofPayloadByDimension(uint64_t block_limit,
                                                                        uint64_t fixed_bytes_per_settlement,
                                                                        uint64_t target_settlements_per_block,
                                                                        uint64_t bytes_per_proof_unit)
{
    if (block_limit == 0 || target_settlements_per_block == 0 || bytes_per_proof_unit == 0) return std::nullopt;
    const uint64_t per_settlement_limit = block_limit / target_settlements_per_block;
    if (per_settlement_limit < fixed_bytes_per_settlement) return std::nullopt;
    return (per_settlement_limit - fixed_bytes_per_settlement) / bytes_per_proof_unit;
}
} // namespace

std::optional<BridgeDataArtifact> BuildBridgeDataArtifact(const BridgeBatchStatement& statement,
                                                          BridgeDataArtifactKind kind,
                                                          const uint256& payload_commitment,
                                                          const uint256& artifact_commitment,
                                                          uint32_t payload_size_bytes,
                                                          uint32_t auxiliary_data_size_bytes)
{
    if (!statement.IsValid() || statement.data_root.IsNull() || !IsValidDataArtifactKindInternal(kind)) return std::nullopt;

    BridgeDataArtifact artifact;
    artifact.kind = kind;
    artifact.statement_hash = ComputeBridgeBatchStatementHash(statement);
    artifact.data_root = statement.data_root;
    artifact.payload_commitment = payload_commitment;
    artifact.artifact_commitment = artifact_commitment;
    artifact.payload_size_bytes = payload_size_bytes;
    artifact.auxiliary_data_size_bytes = auxiliary_data_size_bytes;
    if (!artifact.IsValid()) return std::nullopt;
    return artifact;
}

bool DoesBridgeDataArtifactMatchStatement(const BridgeDataArtifact& artifact,
                                          const BridgeBatchStatement& statement)
{
    if (!artifact.IsValid() || !statement.IsValid()) return false;
    return artifact.statement_hash == ComputeBridgeBatchStatementHash(statement) &&
           artifact.data_root == statement.data_root &&
           !artifact.data_root.IsNull();
}

std::vector<uint8_t> SerializeBridgeDataArtifact(const BridgeDataArtifact& artifact)
{
    if (!artifact.IsValid()) return {};
    DataStream ds{};
    ds << artifact;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeDataArtifact> DeserializeBridgeDataArtifact(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeDataArtifact artifact;
    try {
        ds >> artifact;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !artifact.IsValid()) return std::nullopt;
    return artifact;
}

uint256 ComputeBridgeDataArtifactId(const BridgeDataArtifact& artifact)
{
    const auto bytes = SerializeBridgeDataArtifact(artifact);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Data_Artifact_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

uint64_t GetBridgeDataArtifactStorageBytes(const BridgeDataArtifact& artifact)
{
    if (!artifact.IsValid()) return 0;
    return static_cast<uint64_t>(artifact.payload_size_bytes) +
           static_cast<uint64_t>(artifact.auxiliary_data_size_bytes);
}

std::optional<BridgeAggregateArtifactBundle> BuildBridgeAggregateArtifactBundle(const BridgeBatchStatement& statement,
                                                                                Span<const BridgeProofArtifact> proof_artifacts,
                                                                                Span<const BridgeDataArtifact> data_artifacts)
{
    if (!statement.IsValid() || (proof_artifacts.empty() && data_artifacts.empty())) return std::nullopt;

    BridgeAggregateArtifactBundle bundle;
    bundle.statement_hash = ComputeBridgeBatchStatementHash(statement);
    if (bundle.statement_hash.IsNull()) return std::nullopt;

    for (const auto& artifact : proof_artifacts) {
        if (!DoesBridgeProofArtifactMatchStatement(artifact, statement)) return std::nullopt;
        bundle.proof_artifact_count++;
        const auto payload_bytes = CheckedAddU64(static_cast<uint64_t>(artifact.proof_size_bytes),
                                                 static_cast<uint64_t>(artifact.public_values_size_bytes));
        if (!payload_bytes.has_value()) return std::nullopt;
        const auto total_payload = CheckedAddU64(bundle.proof_payload_bytes, *payload_bytes);
        const auto total_aux = CheckedAddU64(bundle.proof_auxiliary_bytes,
                                             static_cast<uint64_t>(artifact.auxiliary_data_size_bytes));
        if (!total_payload.has_value() || !total_aux.has_value()) return std::nullopt;
        bundle.proof_payload_bytes = *total_payload;
        bundle.proof_auxiliary_bytes = *total_aux;
    }
    if (!proof_artifacts.empty()) {
        bundle.proof_artifact_root = ComputeBridgeProofArtifactRoot(proof_artifacts);
        if (bundle.proof_artifact_root.IsNull()) return std::nullopt;
    }

    for (const auto& artifact : data_artifacts) {
        if (!DoesBridgeDataArtifactMatchStatement(artifact, statement)) return std::nullopt;
        bundle.data_artifact_count++;
        const auto total_payload = CheckedAddU64(bundle.data_availability_payload_bytes,
                                                 static_cast<uint64_t>(artifact.payload_size_bytes));
        const auto total_aux = CheckedAddU64(bundle.data_auxiliary_bytes,
                                             static_cast<uint64_t>(artifact.auxiliary_data_size_bytes));
        if (!total_payload.has_value() || !total_aux.has_value()) return std::nullopt;
        bundle.data_availability_payload_bytes = *total_payload;
        bundle.data_auxiliary_bytes = *total_aux;
    }
    if (!data_artifacts.empty()) {
        bundle.data_artifact_root = ComputeBridgeDataArtifactRoot(data_artifacts);
        if (bundle.data_artifact_root.IsNull()) return std::nullopt;
    }

    if (!bundle.IsValid()) return std::nullopt;
    return bundle;
}

std::vector<uint8_t> SerializeBridgeAggregateArtifactBundle(const BridgeAggregateArtifactBundle& bundle)
{
    if (!bundle.IsValid()) return {};
    DataStream ds{};
    ds << bundle;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeAggregateArtifactBundle> DeserializeBridgeAggregateArtifactBundle(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeAggregateArtifactBundle bundle;
    try {
        ds >> bundle;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !bundle.IsValid()) return std::nullopt;
    return bundle;
}

uint256 ComputeBridgeAggregateArtifactBundleId(const BridgeAggregateArtifactBundle& bundle)
{
    const auto bytes = SerializeBridgeAggregateArtifactBundle(bundle);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Aggregate_Artifact_Bundle_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

uint64_t GetBridgeAggregateArtifactBundleStorageBytes(const BridgeAggregateArtifactBundle& bundle)
{
    if (!bundle.IsValid()) return 0;
    const auto proof_total = CheckedAddU64(bundle.proof_payload_bytes, bundle.proof_auxiliary_bytes);
    const auto data_total = CheckedAddU64(bundle.data_availability_payload_bytes, bundle.data_auxiliary_bytes);
    if (!proof_total.has_value() || !data_total.has_value()) return 0;
    const auto total = CheckedAddU64(*proof_total, *data_total);
    if (!total.has_value()) return 0;
    return *total;
}

std::vector<uint8_t> SerializeBridgeAggregateSettlement(const BridgeAggregateSettlement& settlement)
{
    if (!settlement.IsValid()) return {};
    DataStream ds{};
    ds << settlement;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeAggregateSettlement> DeserializeBridgeAggregateSettlement(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeAggregateSettlement settlement;
    try {
        ds >> settlement;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !settlement.IsValid()) return std::nullopt;
    return settlement;
}

uint256 ComputeBridgeAggregateSettlementId(const BridgeAggregateSettlement& settlement)
{
    const auto bytes = SerializeBridgeAggregateSettlement(settlement);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Aggregate_Settlement_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::optional<BridgeCapacityFootprint> BuildBridgeAggregateSettlementFootprint(const BridgeAggregateSettlement& settlement)
{
    if (!settlement.IsValid()) return std::nullopt;

    uint64_t non_witness_bytes = settlement.base_non_witness_bytes;
    if (const auto total = CheckedAddU64(non_witness_bytes, settlement.state_commitment_bytes)) {
        non_witness_bytes = *total;
    } else {
        return std::nullopt;
    }
    uint64_t witness_bytes = settlement.base_witness_bytes;
    uint64_t data_availability_bytes = 0;
    uint64_t offchain_storage_bytes = settlement.auxiliary_offchain_bytes;

    const auto apply_payload = [&](uint64_t payload_bytes,
                                   BridgeAggregatePayloadLocation location) -> bool {
        if (payload_bytes == 0) return true;
        switch (location) {
        case BridgeAggregatePayloadLocation::INLINE_NON_WITNESS:
            if (const auto total = CheckedAddU64(non_witness_bytes, payload_bytes)) {
                non_witness_bytes = *total;
                return true;
            }
            return false;
        case BridgeAggregatePayloadLocation::INLINE_WITNESS:
            if (const auto total = CheckedAddU64(witness_bytes, payload_bytes)) {
                witness_bytes = *total;
                return true;
            }
            return false;
        case BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY:
            if (const auto total = CheckedAddU64(data_availability_bytes, payload_bytes)) {
                data_availability_bytes = *total;
                return true;
            }
            return false;
        case BridgeAggregatePayloadLocation::OFFCHAIN:
            if (const auto total = CheckedAddU64(offchain_storage_bytes, payload_bytes)) {
                offchain_storage_bytes = *total;
                return true;
            }
            return false;
        }
        return false;
    };

    if (!apply_payload(settlement.proof_payload_bytes, settlement.proof_payload_location) ||
        !apply_payload(settlement.data_availability_payload_bytes, settlement.data_availability_location)) {
        return std::nullopt;
    }

    const auto l1_serialized_bytes = CheckedAddU64(non_witness_bytes, witness_bytes);
    const auto non_witness_weight = CheckedMultiplyU64(non_witness_bytes, 4);
    const auto l1_weight = (l1_serialized_bytes.has_value() && non_witness_weight.has_value())
        ? CheckedAddU64(*non_witness_weight, witness_bytes)
        : std::nullopt;
    if (!l1_serialized_bytes.has_value() || !l1_weight.has_value()) return std::nullopt;

    BridgeCapacityFootprint footprint;
    footprint.l1_serialized_bytes = *l1_serialized_bytes;
    footprint.l1_weight = *l1_weight;
    footprint.l1_data_availability_bytes = data_availability_bytes;
    footprint.control_plane_bytes = settlement.control_plane_bytes;
    footprint.offchain_storage_bytes = offchain_storage_bytes;
    footprint.batched_user_count = settlement.batched_user_count;
    if (!footprint.IsValid()) return std::nullopt;
    return footprint;
}

std::vector<uint8_t> SerializeBridgeShieldedStateProfile(const BridgeShieldedStateProfile& profile)
{
    if (!profile.IsValid()) return {};
    DataStream ds{};
    ds << profile;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeShieldedStateProfile> DeserializeBridgeShieldedStateProfile(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeShieldedStateProfile profile;
    try {
        ds >> profile;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !profile.IsValid()) return std::nullopt;
    return profile;
}

uint256 ComputeBridgeShieldedStateProfileId(const BridgeShieldedStateProfile& profile)
{
    const auto bytes = SerializeBridgeShieldedStateProfile(profile);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Shielded_State_Profile_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::vector<uint8_t> SerializeBridgeShieldedStateRetentionPolicy(const BridgeShieldedStateRetentionPolicy& policy)
{
    if (!policy.IsValid()) return {};
    DataStream ds{};
    ds << policy;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeShieldedStateRetentionPolicy> DeserializeBridgeShieldedStateRetentionPolicy(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeShieldedStateRetentionPolicy policy;
    try {
        ds >> policy;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !policy.IsValid()) return std::nullopt;
    return policy;
}

uint256 ComputeBridgeShieldedStateRetentionPolicyId(const BridgeShieldedStateRetentionPolicy& policy)
{
    const auto bytes = SerializeBridgeShieldedStateRetentionPolicy(policy);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Shielded_State_Retention_Policy_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::optional<BridgeCapacityEstimate> EstimateBridgeCapacity(const BridgeCapacityFootprint& footprint,
                                                             uint64_t block_serialized_limit,
                                                             uint64_t block_weight_limit,
                                                             std::optional<uint64_t> block_data_availability_limit)
{
    if (!footprint.IsValid() || block_serialized_limit == 0 || block_weight_limit == 0) {
        return std::nullopt;
    }
    if (footprint.l1_data_availability_bytes > 0 &&
        (!block_data_availability_limit.has_value() || *block_data_availability_limit == 0)) {
        return std::nullopt;
    }

    BridgeCapacityEstimate estimate;
    estimate.footprint = footprint;
    estimate.block_serialized_limit = block_serialized_limit;
    estimate.block_weight_limit = block_weight_limit;
    estimate.block_data_availability_limit = block_data_availability_limit;
    estimate.fit_by_serialized_size = block_serialized_limit / footprint.l1_serialized_bytes;
    estimate.fit_by_weight = block_weight_limit / footprint.l1_weight;
    uint64_t max_settlements_per_block = std::min(estimate.fit_by_serialized_size, estimate.fit_by_weight);
    uint64_t min_fit = max_settlements_per_block;
    int binding_count = 0;

    if (estimate.fit_by_serialized_size == min_fit) {
        estimate.binding_limit = BridgeCapacityBinding::SERIALIZED_SIZE;
        ++binding_count;
    }
    if (estimate.fit_by_weight == min_fit) {
        estimate.binding_limit = (binding_count == 0) ? BridgeCapacityBinding::WEIGHT : BridgeCapacityBinding::TIED;
        ++binding_count;
    }
    if (footprint.l1_data_availability_bytes > 0) {
        estimate.fit_by_data_availability = *block_data_availability_limit / footprint.l1_data_availability_bytes;
        if (*estimate.fit_by_data_availability < max_settlements_per_block) {
            max_settlements_per_block = *estimate.fit_by_data_availability;
            min_fit = max_settlements_per_block;
            estimate.binding_limit = BridgeCapacityBinding::DATA_AVAILABILITY;
            binding_count = 1;
        } else if (*estimate.fit_by_data_availability == min_fit) {
            estimate.binding_limit = BridgeCapacityBinding::TIED;
            ++binding_count;
        }
    }
    estimate.max_settlements_per_block = max_settlements_per_block;
    if (binding_count > 1) estimate.binding_limit = BridgeCapacityBinding::TIED;

    const auto users_per_block = CheckedMultiplyU64(estimate.max_settlements_per_block, footprint.batched_user_count);
    const auto total_l1_serialized_bytes = CheckedMultiplyU64(estimate.max_settlements_per_block, footprint.l1_serialized_bytes);
    const auto total_l1_weight = CheckedMultiplyU64(estimate.max_settlements_per_block, footprint.l1_weight);
    const auto total_l1_data_availability_bytes = CheckedMultiplyU64(estimate.max_settlements_per_block,
                                                                     footprint.l1_data_availability_bytes);
    const auto total_control_plane_bytes = CheckedMultiplyU64(estimate.max_settlements_per_block, footprint.control_plane_bytes);
    const auto total_offchain_storage_bytes = CheckedMultiplyU64(estimate.max_settlements_per_block, footprint.offchain_storage_bytes);
    if (!users_per_block.has_value() ||
        !total_l1_serialized_bytes.has_value() ||
        !total_l1_weight.has_value() ||
        !total_l1_data_availability_bytes.has_value() ||
        !total_control_plane_bytes.has_value() ||
        !total_offchain_storage_bytes.has_value()) {
        return std::nullopt;
    }

    estimate.users_per_block = *users_per_block;
    estimate.total_l1_serialized_bytes = *total_l1_serialized_bytes;
    estimate.total_l1_weight = *total_l1_weight;
    estimate.total_l1_data_availability_bytes = *total_l1_data_availability_bytes;
    estimate.total_control_plane_bytes = *total_control_plane_bytes;
    estimate.total_offchain_storage_bytes = *total_offchain_storage_bytes;
    return estimate;
}

std::optional<BridgeProofCompressionTarget> BuildBridgeProofCompressionTarget(
    const BridgeAggregateSettlement& settlement,
    const std::optional<BridgeAggregateArtifactBundle>& artifact_bundle,
    uint64_t block_serialized_limit,
    uint64_t block_weight_limit,
    std::optional<uint64_t> block_data_availability_limit,
    uint64_t target_users_per_block)
{
    if (!settlement.IsValid() ||
        block_serialized_limit == 0 ||
        block_weight_limit == 0 ||
        target_users_per_block == 0) {
        return std::nullopt;
    }

    const auto footprint = BuildBridgeAggregateSettlementFootprint(settlement);
    if (!footprint.has_value()) return std::nullopt;

    if ((footprint->l1_data_availability_bytes > 0 ||
         settlement.proof_payload_location == BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY) &&
        (!block_data_availability_limit.has_value() || *block_data_availability_limit == 0)) {
        return std::nullopt;
    }

    if (artifact_bundle.has_value()) {
        if (!artifact_bundle->IsValid() ||
            artifact_bundle->statement_hash != settlement.statement_hash ||
            artifact_bundle->proof_payload_bytes != settlement.proof_payload_bytes ||
            artifact_bundle->data_availability_payload_bytes != settlement.data_availability_payload_bytes) {
            return std::nullopt;
        }
    }

    uint64_t fixed_l1_serialized_bytes = footprint->l1_serialized_bytes;
    uint64_t fixed_l1_weight = footprint->l1_weight;
    uint64_t fixed_l1_data_availability_bytes = footprint->l1_data_availability_bytes;
    uint64_t fixed_offchain_storage_bytes = footprint->offchain_storage_bytes;

    switch (settlement.proof_payload_location) {
    case BridgeAggregatePayloadLocation::INLINE_NON_WITNESS: {
        const auto proof_weight = ComputeProofPayloadWeightBytes(settlement.proof_payload_bytes,
                                                                 settlement.proof_payload_location);
        if (!proof_weight.has_value() ||
            fixed_l1_serialized_bytes < settlement.proof_payload_bytes ||
            fixed_l1_weight < *proof_weight) {
            return std::nullopt;
        }
        fixed_l1_serialized_bytes -= settlement.proof_payload_bytes;
        fixed_l1_weight -= *proof_weight;
        break;
    }
    case BridgeAggregatePayloadLocation::INLINE_WITNESS:
        if (fixed_l1_serialized_bytes < settlement.proof_payload_bytes ||
            fixed_l1_weight < settlement.proof_payload_bytes) {
            return std::nullopt;
        }
        fixed_l1_serialized_bytes -= settlement.proof_payload_bytes;
        fixed_l1_weight -= settlement.proof_payload_bytes;
        break;
    case BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY:
        if (fixed_l1_data_availability_bytes < settlement.proof_payload_bytes) {
            return std::nullopt;
        }
        fixed_l1_data_availability_bytes -= settlement.proof_payload_bytes;
        break;
    case BridgeAggregatePayloadLocation::OFFCHAIN:
        if (fixed_offchain_storage_bytes < settlement.proof_payload_bytes) {
            return std::nullopt;
        }
        fixed_offchain_storage_bytes -= settlement.proof_payload_bytes;
        break;
    }

    const auto target_settlements_per_block = (target_users_per_block +
                                               static_cast<uint64_t>(settlement.batched_user_count) - 1) /
        static_cast<uint64_t>(settlement.batched_user_count);
    if (target_settlements_per_block == 0) return std::nullopt;

    BridgeProofCompressionTarget target;
    target.settlement_id = ComputeBridgeAggregateSettlementId(settlement);
    target.statement_hash = settlement.statement_hash;
    target.block_serialized_limit = block_serialized_limit;
    target.block_weight_limit = block_weight_limit;
    target.block_data_availability_limit = block_data_availability_limit.value_or(0);
    target.target_users_per_block = target_users_per_block;
    target.target_settlements_per_block = target_settlements_per_block;
    target.batched_user_count = settlement.batched_user_count;
    target.proof_artifact_count = artifact_bundle.has_value() ? artifact_bundle->proof_artifact_count : 0;
    target.current_proof_payload_bytes = settlement.proof_payload_bytes;
    target.current_proof_auxiliary_bytes = artifact_bundle.has_value() ? artifact_bundle->proof_auxiliary_bytes : 0;
    target.fixed_l1_serialized_bytes = fixed_l1_serialized_bytes;
    target.fixed_l1_weight = fixed_l1_weight;
    target.fixed_l1_data_availability_bytes = fixed_l1_data_availability_bytes;
    target.fixed_control_plane_bytes = footprint->control_plane_bytes;
    target.fixed_offchain_storage_bytes = fixed_offchain_storage_bytes;
    target.proof_payload_location = settlement.proof_payload_location;
    if (!target.IsValid()) return std::nullopt;
    return target;
}

std::vector<uint8_t> SerializeBridgeProofCompressionTarget(const BridgeProofCompressionTarget& target)
{
    if (!target.IsValid()) return {};
    DataStream ds{};
    ds << target;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeProofCompressionTarget> DeserializeBridgeProofCompressionTarget(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProofCompressionTarget target;
    try {
        ds >> target;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !target.IsValid()) return std::nullopt;
    return target;
}

uint256 ComputeBridgeProofCompressionTargetId(const BridgeProofCompressionTarget& target)
{
    const auto bytes = SerializeBridgeProofCompressionTarget(target);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Compression_Target_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::optional<BridgeProofCompressionEstimate> EstimateBridgeProofCompression(const BridgeProofCompressionTarget& target)
{
    if (!target.IsValid()) return std::nullopt;

    const std::optional<uint64_t> block_data_availability_limit = target.block_data_availability_limit > 0
        ? std::optional<uint64_t>{target.block_data_availability_limit}
        : std::nullopt;

    const auto current_footprint = BuildBridgeProofCompressionFootprint(target, target.current_proof_payload_bytes);
    const auto zero_proof_footprint = BuildBridgeProofCompressionFootprint(target, 0);
    if (!current_footprint.has_value() || !zero_proof_footprint.has_value()) return std::nullopt;

    const auto current_capacity = EstimateBridgeCapacity(*current_footprint,
                                                         target.block_serialized_limit,
                                                         target.block_weight_limit,
                                                         block_data_availability_limit);
    const auto zero_proof_capacity = EstimateBridgeCapacity(*zero_proof_footprint,
                                                            target.block_serialized_limit,
                                                            target.block_weight_limit,
                                                            block_data_availability_limit);
    if (!current_capacity.has_value() || !zero_proof_capacity.has_value()) return std::nullopt;

    BridgeProofCompressionEstimate estimate;
    estimate.target = target;
    estimate.current_capacity = *current_capacity;
    estimate.zero_proof_capacity = *zero_proof_capacity;

    if (target.proof_payload_location == BridgeAggregatePayloadLocation::INLINE_NON_WITNESS ||
        target.proof_payload_location == BridgeAggregatePayloadLocation::INLINE_WITNESS) {
        estimate.max_proof_payload_bytes_by_serialized_size = ComputeMaxProofPayloadByDimension(
            target.block_serialized_limit,
            target.fixed_l1_serialized_bytes,
            target.target_settlements_per_block,
            1);
    }
    if (target.proof_payload_location == BridgeAggregatePayloadLocation::INLINE_NON_WITNESS) {
        estimate.max_proof_payload_bytes_by_weight = ComputeMaxProofPayloadByDimension(
            target.block_weight_limit,
            target.fixed_l1_weight,
            target.target_settlements_per_block,
            4);
    } else if (target.proof_payload_location == BridgeAggregatePayloadLocation::INLINE_WITNESS) {
        estimate.max_proof_payload_bytes_by_weight = ComputeMaxProofPayloadByDimension(
            target.block_weight_limit,
            target.fixed_l1_weight,
            target.target_settlements_per_block,
            1);
    }
    if (target.proof_payload_location == BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY) {
        estimate.max_proof_payload_bytes_by_data_availability = ComputeMaxProofPayloadByDimension(
            target.block_data_availability_limit,
            target.fixed_l1_data_availability_bytes,
            target.target_settlements_per_block,
            1);
    }

    if (zero_proof_capacity->max_settlements_per_block < target.target_settlements_per_block) {
        estimate.achievable = false;
        return estimate;
    }

    if (target.proof_payload_location == BridgeAggregatePayloadLocation::OFFCHAIN) {
        estimate.achievable = current_capacity->max_settlements_per_block >= target.target_settlements_per_block;
        if (estimate.achievable) {
            estimate.modeled_target_capacity = *current_capacity;
            estimate.target_binding_limit = current_capacity->binding_limit;
            estimate.required_proof_payload_reduction_bytes = 0;
        }
        return estimate;
    }

    std::vector<uint64_t> active_limits;
    if (estimate.max_proof_payload_bytes_by_serialized_size.has_value()) {
        active_limits.push_back(*estimate.max_proof_payload_bytes_by_serialized_size);
    }
    if (estimate.max_proof_payload_bytes_by_weight.has_value()) {
        active_limits.push_back(*estimate.max_proof_payload_bytes_by_weight);
    }
    if (estimate.max_proof_payload_bytes_by_data_availability.has_value()) {
        active_limits.push_back(*estimate.max_proof_payload_bytes_by_data_availability);
    }
    if (active_limits.empty()) return std::nullopt;

    const uint64_t required_max_proof_payload_bytes = *std::min_element(active_limits.begin(), active_limits.end());
    estimate.required_max_proof_payload_bytes = required_max_proof_payload_bytes;
    estimate.required_proof_payload_reduction_bytes = target.current_proof_payload_bytes > required_max_proof_payload_bytes
        ? std::optional<uint64_t>{target.current_proof_payload_bytes - required_max_proof_payload_bytes}
        : std::optional<uint64_t>{0};

    const auto modeled_target_footprint = BuildBridgeProofCompressionFootprint(target, required_max_proof_payload_bytes);
    if (!modeled_target_footprint.has_value()) return std::nullopt;
    const auto modeled_target_capacity = EstimateBridgeCapacity(*modeled_target_footprint,
                                                                target.block_serialized_limit,
                                                                target.block_weight_limit,
                                                                block_data_availability_limit);
    if (!modeled_target_capacity.has_value()) return std::nullopt;

    estimate.modeled_target_capacity = *modeled_target_capacity;
    estimate.achievable = modeled_target_capacity->max_settlements_per_block >= target.target_settlements_per_block;
    estimate.target_binding_limit = modeled_target_capacity->binding_limit;
    return estimate;
}

std::optional<BridgeShieldedStateEstimate> EstimateBridgeShieldedStateGrowth(
    const BridgeAggregateSettlement& settlement,
    const BridgeShieldedStateProfile& profile,
    const BridgeCapacityEstimate& capacity,
    uint64_t block_interval_millis)
{
    if (!settlement.IsValid() ||
        !profile.IsValid() ||
        block_interval_millis == 0 ||
        capacity.max_settlements_per_block == 0 ||
        capacity.footprint.batched_user_count != settlement.batched_user_count) {
        return std::nullopt;
    }

    BridgeShieldedStateEstimate estimate;
    estimate.settlement = settlement;
    estimate.profile = profile;
    estimate.capacity = capacity;
    estimate.block_interval_millis = block_interval_millis;
    estimate.note_commitments_per_settlement = settlement.output_count;
    estimate.nullifiers_per_settlement = settlement.input_count;
    estimate.new_wallets_per_settlement = settlement.new_wallet_count;
    estimate.bounded_state_bytes = profile.bounded_anchor_history_bytes;

    const auto checked_mul = [](uint64_t lhs, uint64_t rhs) { return CheckedMultiplyU64(lhs, rhs); };
    const auto checked_add = [](uint64_t lhs, uint64_t rhs) { return CheckedAddU64(lhs, rhs); };

    const auto commitment_index_bytes_per_commitment = checked_add(profile.commitment_index_key_bytes,
                                                                   profile.commitment_index_value_bytes);
    const auto nullifier_index_bytes_per_nullifier = checked_add(profile.nullifier_index_key_bytes,
                                                                 profile.nullifier_index_value_bytes);
    if (!commitment_index_bytes_per_commitment.has_value() || !nullifier_index_bytes_per_nullifier.has_value()) {
        return std::nullopt;
    }

    const auto commitment_index_bytes_per_settlement = checked_mul(estimate.note_commitments_per_settlement,
                                                                   *commitment_index_bytes_per_commitment);
    const auto nullifier_index_bytes_per_settlement = checked_mul(estimate.nullifiers_per_settlement,
                                                                  *nullifier_index_bytes_per_nullifier);
    const auto snapshot_commitment_bytes_per_settlement = checked_mul(estimate.note_commitments_per_settlement,
                                                                      profile.snapshot_commitment_bytes);
    const auto snapshot_nullifier_bytes_per_settlement = checked_mul(estimate.nullifiers_per_settlement,
                                                                     profile.snapshot_nullifier_bytes);
    const auto wallet_materialization_bytes_per_settlement = checked_mul(estimate.new_wallets_per_settlement,
                                                                         profile.wallet_materialization_bytes);
    const auto hot_cache_bytes_per_settlement = checked_mul(estimate.nullifiers_per_settlement,
                                                            profile.nullifier_cache_bytes);
    if (!commitment_index_bytes_per_settlement.has_value() ||
        !nullifier_index_bytes_per_settlement.has_value() ||
        !snapshot_commitment_bytes_per_settlement.has_value() ||
        !snapshot_nullifier_bytes_per_settlement.has_value() ||
        !wallet_materialization_bytes_per_settlement.has_value() ||
        !hot_cache_bytes_per_settlement.has_value()) {
        return std::nullopt;
    }

    const auto snapshot_appendix_bytes_per_settlement = checked_add(*snapshot_commitment_bytes_per_settlement,
                                                                    *snapshot_nullifier_bytes_per_settlement);
    const auto persistent_state_bytes_per_settlement = checked_add(
        *commitment_index_bytes_per_settlement,
        *nullifier_index_bytes_per_settlement);
    if (!snapshot_appendix_bytes_per_settlement.has_value() || !persistent_state_bytes_per_settlement.has_value()) {
        return std::nullopt;
    }
    const auto persistent_plus_wallet = checked_add(*persistent_state_bytes_per_settlement,
                                                    *wallet_materialization_bytes_per_settlement);
    if (!persistent_plus_wallet.has_value()) return std::nullopt;

    estimate.commitment_index_bytes_per_settlement = *commitment_index_bytes_per_settlement;
    estimate.nullifier_index_bytes_per_settlement = *nullifier_index_bytes_per_settlement;
    estimate.snapshot_appendix_bytes_per_settlement = *snapshot_appendix_bytes_per_settlement;
    estimate.wallet_materialization_bytes_per_settlement = *wallet_materialization_bytes_per_settlement;
    estimate.persistent_state_bytes_per_settlement = *persistent_plus_wallet;
    estimate.hot_cache_bytes_per_settlement = *hot_cache_bytes_per_settlement;

    const auto settlements_per_hour_numerator = checked_mul(capacity.max_settlements_per_block, 3'600'000U);
    if (!settlements_per_hour_numerator.has_value()) return std::nullopt;
    const uint64_t settlements_per_hour = *settlements_per_hour_numerator / block_interval_millis;

    const auto assign_block_total = [&](uint64_t per_settlement, uint64_t& out) -> bool {
        const auto total = checked_mul(per_settlement, capacity.max_settlements_per_block);
        if (!total.has_value()) return false;
        out = *total;
        return true;
    };
    const auto assign_hour_total = [&](uint64_t per_settlement, uint64_t& out) -> bool {
        const auto total = checked_mul(per_settlement, settlements_per_hour);
        if (!total.has_value()) return false;
        out = *total;
        return true;
    };

    if (!assign_block_total(estimate.note_commitments_per_settlement, estimate.note_commitments_per_block) ||
        !assign_block_total(estimate.nullifiers_per_settlement, estimate.nullifiers_per_block) ||
        !assign_block_total(estimate.new_wallets_per_settlement, estimate.new_wallets_per_block) ||
        !assign_block_total(estimate.persistent_state_bytes_per_settlement, estimate.persistent_state_bytes_per_block) ||
        !assign_block_total(estimate.snapshot_appendix_bytes_per_settlement, estimate.snapshot_appendix_bytes_per_block) ||
        !assign_block_total(estimate.hot_cache_bytes_per_settlement, estimate.hot_cache_bytes_per_block) ||
        !assign_hour_total(estimate.note_commitments_per_settlement, estimate.note_commitments_per_hour) ||
        !assign_hour_total(estimate.nullifiers_per_settlement, estimate.nullifiers_per_hour) ||
        !assign_hour_total(estimate.new_wallets_per_settlement, estimate.new_wallets_per_hour) ||
        !assign_hour_total(estimate.persistent_state_bytes_per_settlement, estimate.persistent_state_bytes_per_hour) ||
        !assign_hour_total(estimate.snapshot_appendix_bytes_per_settlement, estimate.snapshot_appendix_bytes_per_hour) ||
        !assign_hour_total(estimate.hot_cache_bytes_per_settlement, estimate.hot_cache_bytes_per_hour)) {
        return std::nullopt;
    }

    const auto persistent_state_bytes_per_day = checked_mul(estimate.persistent_state_bytes_per_hour, 24U);
    const auto snapshot_appendix_bytes_per_day = checked_mul(estimate.snapshot_appendix_bytes_per_hour, 24U);
    const auto hot_cache_bytes_per_day = checked_mul(estimate.hot_cache_bytes_per_hour, 24U);
    if (!persistent_state_bytes_per_day.has_value() ||
        !snapshot_appendix_bytes_per_day.has_value() ||
        !hot_cache_bytes_per_day.has_value()) {
        return std::nullopt;
    }
    estimate.persistent_state_bytes_per_day = *persistent_state_bytes_per_day;
    estimate.snapshot_appendix_bytes_per_day = *snapshot_appendix_bytes_per_day;
    estimate.hot_cache_bytes_per_day = *hot_cache_bytes_per_day;
    return estimate;
}

std::optional<BridgeShieldedStateRetentionEstimate> EstimateBridgeShieldedStateRetention(
    const BridgeShieldedStateEstimate& state,
    const BridgeShieldedStateRetentionPolicy& policy)
{
    if (!state.settlement.IsValid() ||
        !state.profile.IsValid() ||
        !policy.IsValid() ||
        state.block_interval_millis == 0 ||
        state.capacity.max_settlements_per_block == 0) {
        return std::nullopt;
    }

    const auto checked_mul = [](uint64_t lhs, uint64_t rhs) { return CheckedMultiplyU64(lhs, rhs); };
    const auto checked_add = [](uint64_t lhs, uint64_t rhs) { return CheckedAddU64(lhs, rhs); };

    BridgeShieldedStateRetentionEstimate estimate;
    estimate.state = state;
    estimate.policy = policy;
    estimate.bounded_snapshot_bytes = state.bounded_state_bytes;

    const auto materialized_wallets_numerator = checked_mul(state.new_wallets_per_settlement,
                                                            static_cast<uint64_t>(policy.wallet_l1_materialization_bps));
    if (!materialized_wallets_numerator.has_value()) return std::nullopt;
    estimate.materialized_wallets_per_settlement = *materialized_wallets_numerator / 10'000U;
    if (estimate.materialized_wallets_per_settlement > state.new_wallets_per_settlement) {
        return std::nullopt;
    }
    estimate.deferred_wallets_per_settlement = state.new_wallets_per_settlement - estimate.materialized_wallets_per_settlement;

    const auto materialized_wallet_bytes_per_settlement = checked_mul(estimate.materialized_wallets_per_settlement,
                                                                      state.profile.wallet_materialization_bytes);
    if (!materialized_wallet_bytes_per_settlement.has_value()) return std::nullopt;
    if (*materialized_wallet_bytes_per_settlement > state.wallet_materialization_bytes_per_settlement) {
        return std::nullopt;
    }
    estimate.deferred_wallet_materialization_bytes_per_settlement =
        state.wallet_materialization_bytes_per_settlement - *materialized_wallet_bytes_per_settlement;

    const uint64_t retained_commitment_index_bytes = policy.retain_commitment_index
        ? state.commitment_index_bytes_per_settlement
        : 0;
    const uint64_t retained_nullifier_index_bytes = policy.retain_nullifier_index
        ? state.nullifier_index_bytes_per_settlement
        : 0;
    const auto retained_persistent_state_without_wallets = checked_add(retained_commitment_index_bytes,
                                                                       retained_nullifier_index_bytes);
    if (!retained_persistent_state_without_wallets.has_value()) return std::nullopt;
    const auto retained_persistent_state_bytes_per_settlement = checked_add(*retained_persistent_state_without_wallets,
                                                                            *materialized_wallet_bytes_per_settlement);
    if (!retained_persistent_state_bytes_per_settlement.has_value()) return std::nullopt;
    estimate.retained_persistent_state_bytes_per_settlement = *retained_persistent_state_bytes_per_settlement;
    if (estimate.retained_persistent_state_bytes_per_settlement > state.persistent_state_bytes_per_settlement) {
        return std::nullopt;
    }
    estimate.externalized_persistent_state_bytes_per_settlement =
        state.persistent_state_bytes_per_settlement - estimate.retained_persistent_state_bytes_per_settlement;

    const auto snapshot_commitment_bytes_per_settlement = checked_mul(state.note_commitments_per_settlement,
                                                                      state.profile.snapshot_commitment_bytes);
    const auto snapshot_nullifier_bytes_per_settlement = checked_mul(state.nullifiers_per_settlement,
                                                                     state.profile.snapshot_nullifier_bytes);
    if (!snapshot_commitment_bytes_per_settlement.has_value() ||
        !snapshot_nullifier_bytes_per_settlement.has_value()) {
        return std::nullopt;
    }
    const uint64_t retained_snapshot_commitment_bytes = policy.snapshot_include_commitments
        ? *snapshot_commitment_bytes_per_settlement
        : 0;
    const uint64_t retained_snapshot_nullifier_bytes = policy.snapshot_include_nullifiers
        ? *snapshot_nullifier_bytes_per_settlement
        : 0;
    const auto snapshot_export_bytes_per_settlement = checked_add(retained_snapshot_commitment_bytes,
                                                                  retained_snapshot_nullifier_bytes);
    if (!snapshot_export_bytes_per_settlement.has_value()) return std::nullopt;
    estimate.snapshot_export_bytes_per_settlement = *snapshot_export_bytes_per_settlement;
    if (estimate.snapshot_export_bytes_per_settlement > state.snapshot_appendix_bytes_per_settlement) {
        return std::nullopt;
    }
    estimate.externalized_snapshot_bytes_per_settlement =
        state.snapshot_appendix_bytes_per_settlement - estimate.snapshot_export_bytes_per_settlement;
    estimate.runtime_hot_cache_bytes_per_settlement = policy.retain_nullifier_index
        ? state.hot_cache_bytes_per_settlement
        : 0;

    const auto assign_totals = [&](uint64_t per_settlement,
                                   uint64_t& per_block,
                                   uint64_t& per_hour,
                                   uint64_t& per_day) -> bool {
        const auto settlements_per_hour_numerator = checked_mul(state.capacity.max_settlements_per_block, 3'600'000U);
        if (!settlements_per_hour_numerator.has_value()) return false;
        const uint64_t settlements_per_hour = *settlements_per_hour_numerator / state.block_interval_millis;
        const auto block_total = checked_mul(per_settlement, state.capacity.max_settlements_per_block);
        const auto hour_total = checked_mul(per_settlement, settlements_per_hour);
        if (!block_total.has_value() || !hour_total.has_value()) return false;
        const auto day_total = checked_mul(*hour_total, 24U);
        if (!day_total.has_value()) return false;
        per_block = *block_total;
        per_hour = *hour_total;
        per_day = *day_total;
        return true;
    };

    if (!assign_totals(estimate.retained_persistent_state_bytes_per_settlement,
                       estimate.retained_persistent_state_bytes_per_block,
                       estimate.retained_persistent_state_bytes_per_hour,
                       estimate.retained_persistent_state_bytes_per_day) ||
        !assign_totals(estimate.externalized_persistent_state_bytes_per_settlement,
                       estimate.externalized_persistent_state_bytes_per_block,
                       estimate.externalized_persistent_state_bytes_per_hour,
                       estimate.externalized_persistent_state_bytes_per_day) ||
        !assign_totals(estimate.deferred_wallet_materialization_bytes_per_settlement,
                       estimate.deferred_wallet_materialization_bytes_per_block,
                       estimate.deferred_wallet_materialization_bytes_per_hour,
                       estimate.deferred_wallet_materialization_bytes_per_day) ||
        !assign_totals(estimate.snapshot_export_bytes_per_settlement,
                       estimate.snapshot_export_bytes_per_block,
                       estimate.snapshot_export_bytes_per_hour,
                       estimate.snapshot_export_bytes_per_day) ||
        !assign_totals(estimate.externalized_snapshot_bytes_per_settlement,
                       estimate.externalized_snapshot_bytes_per_block,
                       estimate.externalized_snapshot_bytes_per_hour,
                       estimate.externalized_snapshot_bytes_per_day) ||
        !assign_totals(estimate.runtime_hot_cache_bytes_per_settlement,
                       estimate.runtime_hot_cache_bytes_per_block,
                       estimate.runtime_hot_cache_bytes_per_hour,
                       estimate.runtime_hot_cache_bytes_per_day)) {
        return std::nullopt;
    }

    if (estimate.snapshot_export_bytes_per_block > 0) {
        const uint64_t available_snapshot_budget = policy.snapshot_target_bytes > estimate.bounded_snapshot_bytes
            ? policy.snapshot_target_bytes - estimate.bounded_snapshot_bytes
            : 0;
        estimate.blocks_to_snapshot_target = available_snapshot_budget / estimate.snapshot_export_bytes_per_block;
        const auto users_to_snapshot_target = checked_mul(*estimate.blocks_to_snapshot_target,
                                                          state.capacity.users_per_block);
        const auto millis_to_snapshot_target = checked_mul(*estimate.blocks_to_snapshot_target,
                                                           state.block_interval_millis);
        if (!users_to_snapshot_target.has_value() || !millis_to_snapshot_target.has_value()) {
            return std::nullopt;
        }
        estimate.users_to_snapshot_target = *users_to_snapshot_target;
        estimate.hours_to_snapshot_target = *millis_to_snapshot_target / 3'600'000U;
        estimate.days_to_snapshot_target = *millis_to_snapshot_target / 86'400'000U;
    }

    return estimate;
}

std::optional<BridgeProverCapacityEstimate> EstimateBridgeProverCapacity(const BridgeCapacityEstimate& l1_capacity,
                                                                         const BridgeProverFootprint& footprint)
{
    if (!footprint.IsValid()) return std::nullopt;

    BridgeProverCapacityEstimate estimate;
    estimate.footprint = footprint;
    estimate.l1_capacity = l1_capacity;

    const auto l1_settlements_per_hour_limit = CheckedMultiplyU64(l1_capacity.max_settlements_per_block, 3'600'000U);
    const auto l1_users_per_hour_limit = CheckedMultiplyU64(l1_capacity.users_per_block, 3'600'000U);
    if (!l1_settlements_per_hour_limit.has_value() || !l1_users_per_hour_limit.has_value()) return std::nullopt;
    estimate.l1_settlements_per_hour_limit = *l1_settlements_per_hour_limit / footprint.block_interval_millis;
    estimate.l1_users_per_hour_limit = *l1_users_per_hour_limit / footprint.block_interval_millis;

    const auto assign_lane = [&](const std::optional<BridgeProverLane>& lane,
                                 std::optional<BridgeProverLaneEstimate>& out) -> bool {
        if (!lane.has_value()) return true;
        out = EstimateBridgeProverLane(*lane,
                                       l1_capacity,
                                       footprint.block_interval_millis,
                                       estimate.l1_settlements_per_hour_limit,
                                       estimate.l1_users_per_hour_limit);
        return out.has_value();
    };

    if (!assign_lane(footprint.native, estimate.native) ||
        !assign_lane(footprint.cpu, estimate.cpu) ||
        !assign_lane(footprint.gpu, estimate.gpu) ||
        !assign_lane(footprint.network, estimate.network)) {
        return std::nullopt;
    }

    return estimate;
}

std::optional<BridgeProverSample> BuildBridgeProverSample(const BridgeProofArtifact& artifact,
                                                          uint64_t native_millis,
                                                          uint64_t cpu_millis,
                                                          uint64_t gpu_millis,
                                                          uint64_t network_millis,
                                                          uint64_t peak_memory_bytes)
{
    if (!artifact.IsValid()) return std::nullopt;
    const auto descriptor = BuildBridgeProofDescriptorFromArtifact(artifact);
    if (!descriptor.has_value()) return std::nullopt;

    BridgeProverSample sample;
    sample.statement_hash = artifact.statement_hash;
    sample.proof_artifact_id = ComputeBridgeProofArtifactId(artifact);
    sample.proof_system_id = descriptor->proof_system_id;
    sample.verifier_key_hash = descriptor->verifier_key_hash;
    sample.artifact_storage_bytes = GetBridgeProofArtifactStorageBytes(artifact);
    sample.native_millis = native_millis;
    sample.cpu_millis = cpu_millis;
    sample.gpu_millis = gpu_millis;
    sample.network_millis = network_millis;
    sample.peak_memory_bytes = peak_memory_bytes;
    if (!sample.IsValid()) return std::nullopt;
    return sample;
}

std::vector<uint8_t> SerializeBridgeProverSample(const BridgeProverSample& sample)
{
    if (!sample.IsValid()) return {};
    DataStream ds;
    ds << sample;
    const auto bytes = MakeUCharSpan(ds);
    return {bytes.begin(), bytes.end()};
}

std::optional<BridgeProverSample> DeserializeBridgeProverSample(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProverSample sample;
    try {
        ds >> sample;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !sample.IsValid()) return std::nullopt;
    return sample;
}

uint256 ComputeBridgeProverSampleId(const BridgeProverSample& sample)
{
    const auto bytes = SerializeBridgeProverSample(sample);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Prover_Sample_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::optional<BridgeProverProfile> BuildBridgeProverProfile(Span<const BridgeProverSample> samples)
{
    if (samples.empty()) return std::nullopt;

    BridgeProverProfile profile;
    profile.statement_hash = samples.front().statement_hash;
    std::set<uint256> unique_sample_ids;
    std::set<uint256> unique_artifact_ids;
    std::vector<uint256> level;
    level.reserve(samples.size());

    for (const auto& sample : samples) {
        if (!sample.IsValid() || sample.statement_hash != profile.statement_hash) return std::nullopt;
        const uint256 sample_id = ComputeBridgeProverSampleId(sample);
        if (sample_id.IsNull()) return std::nullopt;
        if (!unique_sample_ids.emplace(sample_id).second) return std::nullopt;
        if (!unique_artifact_ids.emplace(sample.proof_artifact_id).second) return std::nullopt;
        level.push_back(sample_id);

        const auto total_artifact_storage_bytes = CheckedAddU64(profile.total_artifact_storage_bytes,
                                                                sample.artifact_storage_bytes);
        const auto total_peak_memory_bytes = CheckedAddU64(profile.total_peak_memory_bytes,
                                                           sample.peak_memory_bytes);
        const auto native_millis_per_settlement = CheckedAddU64(profile.native_millis_per_settlement,
                                                                sample.native_millis);
        const auto cpu_millis_per_settlement = CheckedAddU64(profile.cpu_millis_per_settlement,
                                                             sample.cpu_millis);
        const auto gpu_millis_per_settlement = CheckedAddU64(profile.gpu_millis_per_settlement,
                                                             sample.gpu_millis);
        const auto network_millis_per_settlement = CheckedAddU64(profile.network_millis_per_settlement,
                                                                 sample.network_millis);
        if (!total_artifact_storage_bytes.has_value() ||
            !total_peak_memory_bytes.has_value() ||
            !native_millis_per_settlement.has_value() ||
            !cpu_millis_per_settlement.has_value() ||
            !gpu_millis_per_settlement.has_value() ||
            !network_millis_per_settlement.has_value()) {
            return std::nullopt;
        }

        profile.total_artifact_storage_bytes = *total_artifact_storage_bytes;
        profile.total_peak_memory_bytes = *total_peak_memory_bytes;
        profile.max_peak_memory_bytes = std::max(profile.max_peak_memory_bytes, sample.peak_memory_bytes);
        profile.native_millis_per_settlement = *native_millis_per_settlement;
        profile.cpu_millis_per_settlement = *cpu_millis_per_settlement;
        profile.gpu_millis_per_settlement = *gpu_millis_per_settlement;
        profile.network_millis_per_settlement = *network_millis_per_settlement;
    }

    profile.sample_count = static_cast<uint32_t>(samples.size());
    std::sort(level.begin(), level.end());
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeProverSampleNode(left, right);
            if (parent.IsNull()) return std::nullopt;
            next.push_back(parent);
        }
        level = std::move(next);
    }
    profile.sample_root = level.front();
    if (!profile.IsValid()) return std::nullopt;
    return profile;
}

std::vector<uint8_t> SerializeBridgeProverProfile(const BridgeProverProfile& profile)
{
    if (!profile.IsValid()) return {};
    DataStream ds;
    ds << profile;
    const auto bytes = MakeUCharSpan(ds);
    return {bytes.begin(), bytes.end()};
}

std::optional<BridgeProverProfile> DeserializeBridgeProverProfile(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProverProfile profile;
    try {
        ds >> profile;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !profile.IsValid()) return std::nullopt;
    return profile;
}

uint256 ComputeBridgeProverProfileId(const BridgeProverProfile& profile)
{
    const auto bytes = SerializeBridgeProverProfile(profile);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Prover_Profile_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

namespace {
[[nodiscard]] size_t BridgePercentileIndex(size_t count, size_t percentile)
{
    assert(count > 0);
    assert(percentile > 0 && percentile <= 100);
    const size_t scaled = (percentile * count + 99) / 100;
    return std::min(count - 1, scaled - 1);
}

[[nodiscard]] std::optional<BridgeProverMetricSummary> BuildBridgeProverMetricSummary(std::vector<uint64_t> values)
{
    if (values.empty()) return std::nullopt;
    std::sort(values.begin(), values.end());

    BridgeProverMetricSummary summary;
    summary.min = values.front();
    summary.p50 = values[BridgePercentileIndex(values.size(), 50)];
    summary.p90 = values[BridgePercentileIndex(values.size(), 90)];
    summary.max = values.back();
    if (!summary.IsValid()) return std::nullopt;
    return summary;
}
} // namespace

std::optional<BridgeProverBenchmark> BuildBridgeProverBenchmark(Span<const BridgeProverProfile> profiles)
{
    if (profiles.empty()) return std::nullopt;

    BridgeProverBenchmark benchmark;
    benchmark.statement_hash = profiles.front().statement_hash;
    benchmark.sample_count_per_profile = profiles.front().sample_count;
    benchmark.artifact_storage_bytes_per_profile = profiles.front().total_artifact_storage_bytes;

    std::set<uint256> unique_profile_ids;
    std::vector<uint256> level;
    level.reserve(profiles.size());

    std::vector<uint64_t> total_peak_memory_bytes_values;
    std::vector<uint64_t> max_peak_memory_bytes_values;
    std::vector<uint64_t> native_values;
    std::vector<uint64_t> cpu_values;
    std::vector<uint64_t> gpu_values;
    std::vector<uint64_t> network_values;
    total_peak_memory_bytes_values.reserve(profiles.size());
    max_peak_memory_bytes_values.reserve(profiles.size());
    native_values.reserve(profiles.size());
    cpu_values.reserve(profiles.size());
    gpu_values.reserve(profiles.size());
    network_values.reserve(profiles.size());

    for (const auto& profile : profiles) {
        if (!profile.IsValid() ||
            profile.statement_hash != benchmark.statement_hash ||
            profile.sample_count != benchmark.sample_count_per_profile ||
            profile.total_artifact_storage_bytes != benchmark.artifact_storage_bytes_per_profile) {
            return std::nullopt;
        }

        const uint256 profile_id = ComputeBridgeProverProfileId(profile);
        if (profile_id.IsNull()) return std::nullopt;
        if (!unique_profile_ids.emplace(profile_id).second) return std::nullopt;
        level.push_back(profile_id);

        total_peak_memory_bytes_values.push_back(profile.total_peak_memory_bytes);
        max_peak_memory_bytes_values.push_back(profile.max_peak_memory_bytes);
        native_values.push_back(profile.native_millis_per_settlement);
        cpu_values.push_back(profile.cpu_millis_per_settlement);
        gpu_values.push_back(profile.gpu_millis_per_settlement);
        network_values.push_back(profile.network_millis_per_settlement);
    }

    benchmark.profile_count = static_cast<uint32_t>(profiles.size());
    std::sort(level.begin(), level.end());
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeProverProfileNode(left, right);
            if (parent.IsNull()) return std::nullopt;
            next.push_back(parent);
        }
        level = std::move(next);
    }
    benchmark.profile_root = level.front();

    const auto total_peak_memory_summary = BuildBridgeProverMetricSummary(std::move(total_peak_memory_bytes_values));
    const auto max_peak_memory_summary = BuildBridgeProverMetricSummary(std::move(max_peak_memory_bytes_values));
    const auto native_summary = BuildBridgeProverMetricSummary(std::move(native_values));
    const auto cpu_summary = BuildBridgeProverMetricSummary(std::move(cpu_values));
    const auto gpu_summary = BuildBridgeProverMetricSummary(std::move(gpu_values));
    const auto network_summary = BuildBridgeProverMetricSummary(std::move(network_values));
    if (!total_peak_memory_summary.has_value() ||
        !max_peak_memory_summary.has_value() ||
        !native_summary.has_value() ||
        !cpu_summary.has_value() ||
        !gpu_summary.has_value() ||
        !network_summary.has_value()) {
        return std::nullopt;
    }

    benchmark.total_peak_memory_bytes = *total_peak_memory_summary;
    benchmark.max_peak_memory_bytes = *max_peak_memory_summary;
    benchmark.native_millis_per_settlement = *native_summary;
    benchmark.cpu_millis_per_settlement = *cpu_summary;
    benchmark.gpu_millis_per_settlement = *gpu_summary;
    benchmark.network_millis_per_settlement = *network_summary;
    if (!benchmark.IsValid()) return std::nullopt;
    return benchmark;
}

std::vector<uint8_t> SerializeBridgeProverBenchmark(const BridgeProverBenchmark& benchmark)
{
    if (!benchmark.IsValid()) return {};
    DataStream ds;
    ds << benchmark;
    const auto bytes = MakeUCharSpan(ds);
    return {bytes.begin(), bytes.end()};
}

std::optional<BridgeProverBenchmark> DeserializeBridgeProverBenchmark(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProverBenchmark benchmark;
    try {
        ds >> benchmark;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !benchmark.IsValid()) return std::nullopt;
    return benchmark;
}

uint256 ComputeBridgeProverBenchmarkId(const BridgeProverBenchmark& benchmark)
{
    const auto bytes = SerializeBridgeProverBenchmark(benchmark);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Prover_Benchmark_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

uint64_t SelectBridgeProverMetric(const BridgeProverMetricSummary& summary,
                                  BridgeProverBenchmarkStatistic statistic)
{
    switch (statistic) {
    case BridgeProverBenchmarkStatistic::MIN:
        return summary.min;
    case BridgeProverBenchmarkStatistic::P50:
        return summary.p50;
    case BridgeProverBenchmarkStatistic::P90:
        return summary.p90;
    case BridgeProverBenchmarkStatistic::MAX:
        return summary.max;
    }
    return 0;
}

std::optional<BridgeProofArtifact> BuildBridgeProofArtifact(const BridgeBatchStatement& statement,
                                                            const BridgeProofAdapter& adapter,
                                                            const uint256& verifier_key_hash,
                                                            const uint256& proof_commitment,
                                                            const uint256& artifact_commitment,
                                                            uint32_t proof_size_bytes,
                                                            uint32_t public_values_size_bytes,
                                                            uint32_t auxiliary_data_size_bytes)
{
    if (!statement.IsValid() || !adapter.IsValid() || artifact_commitment.IsNull()) return std::nullopt;
    const auto claim = BuildBridgeProofClaimFromAdapter(statement, adapter);
    if (!claim.has_value()) return std::nullopt;
    const auto receipt = BuildBridgeProofReceiptFromProfile(statement,
                                                            adapter.profile,
                                                            verifier_key_hash,
                                                            *claim,
                                                            proof_commitment);
    if (!receipt.has_value()) return std::nullopt;

    BridgeProofArtifact artifact;
    artifact.adapter = adapter;
    artifact.statement_hash = receipt->statement_hash;
    artifact.verifier_key_hash = receipt->verifier_key_hash;
    artifact.public_values_hash = receipt->public_values_hash;
    artifact.proof_commitment = receipt->proof_commitment;
    artifact.artifact_commitment = artifact_commitment;
    artifact.proof_size_bytes = proof_size_bytes;
    artifact.public_values_size_bytes = public_values_size_bytes;
    artifact.auxiliary_data_size_bytes = auxiliary_data_size_bytes;
    if (!artifact.IsValid()) return std::nullopt;
    return artifact;
}

bool DoesBridgeProofArtifactMatchStatement(const BridgeProofArtifact& artifact,
                                           const BridgeBatchStatement& statement)
{
    if (!artifact.IsValid() || !statement.IsValid()) return false;
    if (artifact.statement_hash != ComputeBridgeBatchStatementHash(statement)) return false;
    const auto claim = BuildBridgeProofClaimFromAdapter(statement, artifact.adapter);
    if (!claim.has_value()) return false;
    return artifact.public_values_hash == ComputeBridgeProofClaimHash(*claim);
}

std::optional<BridgeProofDescriptor> BuildBridgeProofDescriptorFromProfile(const BridgeProofSystemProfile& profile,
                                                                           const uint256& verifier_key_hash)
{
    if (!profile.IsValid() || verifier_key_hash.IsNull()) return std::nullopt;
    BridgeProofDescriptor descriptor;
    descriptor.proof_system_id = ComputeBridgeProofSystemId(profile);
    descriptor.verifier_key_hash = verifier_key_hash;
    if (!descriptor.IsValid()) return std::nullopt;
    return descriptor;
}

std::optional<BridgeProofDescriptor> BuildBridgeProofDescriptorFromAdapter(const BridgeProofAdapter& adapter,
                                                                           const uint256& verifier_key_hash)
{
    if (!adapter.IsValid()) return std::nullopt;
    return BuildBridgeProofDescriptorFromProfile(adapter.profile, verifier_key_hash);
}

std::optional<BridgeProofDescriptor> BuildBridgeProofDescriptorFromArtifact(const BridgeProofArtifact& artifact)
{
    if (!artifact.IsValid()) return std::nullopt;
    return BuildBridgeProofDescriptorFromAdapter(artifact.adapter, artifact.verifier_key_hash);
}

std::optional<BridgeProofAdapter> BuildCanonicalBridgeProofAdapter(BridgeProofClaimKind claim_kind,
                                                                   size_t variant_index)
{
    size_t match_count{0};
    for (const auto& adapter_template : CANONICAL_BRIDGE_PROOF_ADAPTERS) {
        if (adapter_template.claim_kind == claim_kind) {
            ++match_count;
        }
    }
    if (match_count == 0) {
        return std::nullopt;
    }

    const size_t target_match = variant_index % match_count;
    size_t current_match{0};
    for (const auto& adapter_template : CANONICAL_BRIDGE_PROOF_ADAPTERS) {
        if (adapter_template.claim_kind != claim_kind) {
            continue;
        }
        if (current_match++ != target_match) {
            continue;
        }
        const auto profile = BuildCanonicalBridgeProofSystemProfile(adapter_template);
        if (!profile.has_value()) {
            return std::nullopt;
        }
        BridgeProofAdapter adapter;
        adapter.profile = *profile;
        adapter.claim_kind = claim_kind;
        if (adapter.IsValid()) {
            return adapter;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

bool IsCanonicalBridgeProofSystemId(const uint256& proof_system_id)
{
    if (proof_system_id.IsNull()) return false;
    for (const auto& adapter_template : CANONICAL_BRIDGE_PROOF_ADAPTERS) {
        const auto profile = BuildCanonicalBridgeProofSystemProfile(adapter_template);
        if (!profile.has_value()) {
            continue;
        }
        if (ComputeBridgeProofSystemId(*profile) == proof_system_id) {
            return true;
        }
    }
    return false;
}

uint256 ComputeBridgeProofDescriptorLeafHash(const BridgeProofDescriptor& descriptor)
{
    if (!descriptor.IsValid()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Descriptor_Leaf_V1"};
    hw << descriptor;
    return hw.GetSHA256();
}

uint256 ComputeBridgeProofPolicyRoot(Span<const BridgeProofDescriptor> descriptors)
{
    if (descriptors.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(descriptors.size());
    for (const auto& descriptor : descriptors) {
        const uint256 leaf_hash = ComputeBridgeProofDescriptorLeafHash(descriptor);
        if (leaf_hash.IsNull()) return uint256{};
        level.push_back(leaf_hash);
    }
    std::sort(level.begin(), level.end());

    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeProofPolicyNode(left, right);
            if (parent.IsNull()) return uint256{};
            next.push_back(parent);
        }
        level = std::move(next);
    }
    return level.front();
}

std::optional<shielded::BridgeProofPolicyCommitment> BuildBridgeProofPolicyCommitment(Span<const BridgeProofDescriptor> descriptors,
                                                                                       size_t required_receipts)
{
    if (descriptors.empty() || required_receipts == 0) return std::nullopt;

    std::set<BridgeProofDescriptorId> unique_descriptors;
    for (const auto& descriptor : descriptors) {
        if (!descriptor.IsValid()) return std::nullopt;
        if (!unique_descriptors.emplace(MakeBridgeProofDescriptorId(descriptor)).second) return std::nullopt;
    }

    shielded::BridgeProofPolicyCommitment proof_policy;
    proof_policy.descriptor_count = static_cast<uint32_t>(descriptors.size());
    proof_policy.required_receipts = static_cast<uint32_t>(required_receipts);
    proof_policy.descriptor_root = ComputeBridgeProofPolicyRoot(descriptors);
    if (!proof_policy.IsValid()) return std::nullopt;
    return proof_policy;
}

std::vector<uint8_t> SerializeBridgeProofPolicyProof(const shielded::BridgeProofPolicyProof& proof)
{
    if (!proof.IsValid()) return {};
    DataStream ds{};
    ds << proof;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<shielded::BridgeProofPolicyProof> DeserializeBridgeProofPolicyProof(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    shielded::BridgeProofPolicyProof proof;
    ds >> proof;
    if (!ds.empty() || !proof.IsValid()) return std::nullopt;
    return proof;
}

std::optional<shielded::BridgeProofPolicyProof> BuildBridgeProofPolicyProof(Span<const BridgeProofDescriptor> descriptors,
                                                                            const BridgeProofDescriptor& descriptor)
{
    if (!descriptor.IsValid() || descriptors.empty()) return std::nullopt;

    std::set<BridgeProofDescriptorId> unique_descriptors;
    std::vector<std::pair<uint256, BridgeProofDescriptorId>> leaves;
    leaves.reserve(descriptors.size());
    for (const auto& candidate : descriptors) {
        if (!candidate.IsValid()) return std::nullopt;
        const BridgeProofDescriptorId candidate_id = MakeBridgeProofDescriptorId(candidate);
        if (!unique_descriptors.emplace(candidate_id).second) return std::nullopt;
        const uint256 leaf_hash = ComputeBridgeProofDescriptorLeafHash(candidate);
        if (leaf_hash.IsNull()) return std::nullopt;
        leaves.emplace_back(leaf_hash, candidate_id);
    }
    std::sort(leaves.begin(), leaves.end(), [](const auto& a, const auto& b) {
        if (a.first == b.first) return a.second < b.second;
        return a.first < b.first;
    });

    const BridgeProofDescriptorId target_id = MakeBridgeProofDescriptorId(descriptor);
    const uint256 target_hash = ComputeBridgeProofDescriptorLeafHash(descriptor);
    if (target_hash.IsNull()) return std::nullopt;

    size_t index{0};
    bool found{false};
    for (; index < leaves.size(); ++index) {
        if (leaves[index].first == target_hash && leaves[index].second == target_id) {
            found = true;
            break;
        }
    }
    if (!found) return std::nullopt;

    shielded::BridgeProofPolicyProof proof;
    proof.leaf_index = static_cast<uint32_t>(index);

    std::vector<uint256> level;
    level.reserve(leaves.size());
    for (const auto& leaf : leaves) {
        level.push_back(leaf.first);
    }

    while (level.size() > 1) {
        const size_t sibling_index = (index % 2 == 0)
            ? ((index + 1 < level.size()) ? index + 1 : index)
            : index - 1;
        proof.siblings.push_back(level[sibling_index]);

        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeProofPolicyNode(left, right);
            if (parent.IsNull()) return std::nullopt;
            next.push_back(parent);
        }
        level = std::move(next);
        index /= 2;
    }

    if (!proof.IsValid()) return std::nullopt;
    return proof;
}

bool VerifyBridgeProofPolicyProof(const shielded::BridgeProofPolicyCommitment& proof_policy,
                                  const BridgeProofDescriptor& descriptor,
                                  const shielded::BridgeProofPolicyProof& proof)
{
    if (!proof_policy.IsValid() || !descriptor.IsValid() || !proof.IsValid()) return false;
    if (proof.leaf_index >= proof_policy.descriptor_count) return false;

    uint32_t expected_depth{0};
    for (uint32_t width = proof_policy.descriptor_count; width > 1; width = (width + 1) / 2) {
        ++expected_depth;
    }
    if (proof.siblings.size() != expected_depth) return false;

    uint256 hash = ComputeBridgeProofDescriptorLeafHash(descriptor);
    if (hash.IsNull()) return false;

    uint32_t index = proof.leaf_index;
    uint32_t width = proof_policy.descriptor_count;
    for (size_t i = 0; i < proof.siblings.size(); ++i) {
        const uint256& sibling = proof.siblings[i];
        if (sibling.IsNull()) return false;

        if ((index % 2) == 0) {
            const bool has_distinct_right = index + 1 < width;
            if (!has_distinct_right && sibling != hash) return false;
            hash = HashBridgeProofPolicyNode(hash, has_distinct_right ? sibling : hash);
        } else {
            hash = HashBridgeProofPolicyNode(sibling, hash);
        }
        if (hash.IsNull()) return false;

        index /= 2;
        width = (width + 1) / 2;
    }

    return hash == proof_policy.descriptor_root;
}

bool IsValidRefundLockHeight(uint32_t refund_lock_height)
{
    return refund_lock_height > 0 && refund_lock_height < std::numeric_limits<int32_t>::max();
}

bool IsValidBridgeBatchLeafKind(BridgeBatchLeafKind kind)
{
    return IsValidBatchLeafKindInternal(kind);
}

bool IsWellFormedBridgeAttestation(const BridgeAttestationMessage& message)
{
    if (message.version != 1 && message.version != 2 && message.version != 3) return false;
    if (message.genesis_hash.IsNull()) return false;
    if (message.direction != BridgeDirection::BRIDGE_IN && message.direction != BridgeDirection::BRIDGE_OUT) return false;
    if (!message.ids.IsValid()) return false;
    if (message.ctv_hash.IsNull()) return false;
    if (!IsValidRefundLockHeight(message.refund_lock_height)) return false;
    if (message.version == 1) {
        return message.batch_entry_count == 0 &&
               message.batch_total_amount == 0 &&
               message.batch_root.IsNull() &&
               message.external_anchor.IsEmpty();
    }
    if (message.batch_entry_count == 0) return false;
    if (!MoneyRange(message.batch_total_amount) || message.batch_total_amount <= 0) return false;
    if (message.batch_root.IsNull()) return false;
    if (message.version == 2) return message.external_anchor.IsEmpty();
    return message.external_anchor.IsValid();
}

bool DoesBridgeAttestationMatchGenesis(const BridgeAttestationMessage& message, const uint256& genesis_hash)
{
    return IsWellFormedBridgeAttestation(message) && message.genesis_hash == genesis_hash;
}

std::vector<uint8_t> SerializeBridgeBatchStatement(const BridgeBatchStatement& statement)
{
    if (!statement.IsValid()) return {};
    DataStream ds{};
    ds << statement;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeBatchStatement> DeserializeBridgeBatchStatement(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeBatchStatement statement;
    try {
        ds >> statement;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !statement.IsValid()) return std::nullopt;
    return statement;
}

uint256 ComputeBridgeBatchStatementHash(const BridgeBatchStatement& statement)
{
    const auto bytes = SerializeBridgeBatchStatement(statement);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_Statement_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::vector<uint8_t> SerializeBridgeBatchReceiptMessage(const BridgeBatchReceipt& receipt)
{
    if (!receipt.IsMessageValid()) return {};
    DataStream ds{};
    ds << receipt.version;
    ds << receipt.statement;
    ds << receipt.attestor;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::vector<uint8_t> SerializeBridgeBatchReceipt(const BridgeBatchReceipt& receipt)
{
    if (!receipt.IsValid()) return {};
    DataStream ds{};
    ds << receipt;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeBatchReceipt> DeserializeBridgeBatchReceipt(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeBatchReceipt receipt;
    try {
        ds >> receipt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !receipt.IsValid()) return std::nullopt;
    return receipt;
}

uint256 ComputeBridgeBatchReceiptHash(const BridgeBatchReceipt& receipt)
{
    const auto bytes = SerializeBridgeBatchReceiptMessage(receipt);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_Receipt_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

bool VerifyBridgeBatchReceipt(const BridgeBatchReceipt& receipt)
{
    if (!receipt.IsMessageValid() || !receipt.HasSignature()) return false;
    const uint256 hash = ComputeBridgeBatchReceiptHash(receipt);
    if (hash.IsNull()) return false;
    return CPQPubKey{receipt.attestor.algo, receipt.attestor.pubkey}.Verify(hash, receipt.signature);
}

uint256 ComputeBridgeBatchReceiptLeafHash(const BridgeBatchReceipt& receipt)
{
    const auto bytes = SerializeBridgeBatchReceipt(receipt);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_Receipt_Leaf_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

size_t CountDistinctBridgeBatchReceiptAttestors(Span<const BridgeBatchReceipt> receipts)
{
    std::set<BridgeKeyId> attestors;
    for (const auto& receipt : receipts) {
        if (!receipt.attestor.IsValid()) return 0;
        attestors.emplace(MakeBridgeKeyId(receipt.attestor));
    }
    return attestors.size();
}

uint256 ComputeBridgeBatchReceiptRoot(Span<const BridgeBatchReceipt> receipts)
{
    if (receipts.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(receipts.size());
    for (const auto& receipt : receipts) {
        const uint256 leaf_hash = ComputeBridgeBatchReceiptLeafHash(receipt);
        if (leaf_hash.IsNull()) return uint256{};
        level.push_back(leaf_hash);
    }
    std::sort(level.begin(), level.end());

    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeBatchNode(left, right);
            if (parent.IsNull()) return uint256{};
            next.push_back(parent);
        }
        level = std::move(next);
    }
    return level.front();
}

std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromStatement(const BridgeBatchStatement& statement,
                                                                           Span<const BridgeBatchReceipt> receipts)
{
    if (!statement.IsValid() || receipts.empty()) return std::nullopt;
    if (statement.proof_policy.IsValid()) return std::nullopt;
    const uint256 statement_hash = ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) return std::nullopt;

    for (const auto& receipt : receipts) {
        if (!VerifyBridgeBatchReceipt(receipt)) return std::nullopt;
        if (ComputeBridgeBatchStatementHash(receipt.statement) != statement_hash) return std::nullopt;
    }
    if (CountDistinctBridgeBatchReceiptAttestors(receipts) != receipts.size()) return std::nullopt;

    BridgeExternalAnchor anchor;
    anchor.domain_id = statement.domain_id;
    anchor.source_epoch = statement.source_epoch;
    anchor.data_root = statement.data_root;
    anchor.verification_root = ComputeBridgeBatchReceiptRoot(receipts);
    if (!anchor.IsValid()) return std::nullopt;
    return anchor;
}

std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromProfile(const BridgeBatchStatement& statement,
                                                                     const BridgeProofSystemProfile& profile,
                                                                     const uint256& verifier_key_hash,
                                                                     const uint256& public_values_hash,
                                                                     const uint256& proof_commitment)
{
    if (!statement.IsValid() || !profile.IsValid()) return std::nullopt;
    const auto descriptor = BuildBridgeProofDescriptorFromProfile(profile, verifier_key_hash);
    if (!descriptor.has_value() || public_values_hash.IsNull() || proof_commitment.IsNull()) return std::nullopt;

    BridgeProofReceipt receipt;
    receipt.statement_hash = ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor->proof_system_id;
    receipt.verifier_key_hash = descriptor->verifier_key_hash;
    receipt.public_values_hash = public_values_hash;
    receipt.proof_commitment = proof_commitment;
    if (!receipt.IsValid()) return std::nullopt;
    return receipt;
}

std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromProfile(const BridgeBatchStatement& statement,
                                                                     const BridgeProofSystemProfile& profile,
                                                                     const uint256& verifier_key_hash,
                                                                     const BridgeProofClaim& claim,
                                                                     const uint256& proof_commitment)
{
    if (!claim.IsValid()) return std::nullopt;
    if (!DoesBridgeProofClaimMatchStatement(claim, statement)) return std::nullopt;
    const uint256 public_values_hash = ComputeBridgeProofClaimHash(claim);
    if (public_values_hash.IsNull()) return std::nullopt;
    return BuildBridgeProofReceiptFromProfile(statement, profile, verifier_key_hash, public_values_hash, proof_commitment);
}

std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromAdapter(const BridgeBatchStatement& statement,
                                                                     const BridgeProofAdapter& adapter,
                                                                     const uint256& verifier_key_hash,
                                                                     const uint256& proof_commitment)
{
    if (!adapter.IsValid()) return std::nullopt;
    const auto claim = BuildBridgeProofClaimFromAdapter(statement, adapter);
    if (!claim.has_value()) return std::nullopt;
    return BuildBridgeProofReceiptFromProfile(statement, adapter.profile, verifier_key_hash, *claim, proof_commitment);
}

std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromArtifact(const BridgeProofArtifact& artifact)
{
    if (!artifact.IsValid()) return std::nullopt;
    const auto descriptor = BuildBridgeProofDescriptorFromArtifact(artifact);
    if (!descriptor.has_value()) return std::nullopt;

    BridgeProofReceipt receipt;
    receipt.statement_hash = artifact.statement_hash;
    receipt.proof_system_id = descriptor->proof_system_id;
    receipt.verifier_key_hash = descriptor->verifier_key_hash;
    receipt.public_values_hash = artifact.public_values_hash;
    receipt.proof_commitment = artifact.proof_commitment;
    if (!receipt.IsValid()) return std::nullopt;
    return receipt;
}

std::vector<uint8_t> SerializeBridgeVerificationBundle(const BridgeVerificationBundle& bundle)
{
    if (!bundle.IsValid()) return {};
    DataStream ds{};
    ds << bundle;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeVerificationBundle> DeserializeBridgeVerificationBundle(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeVerificationBundle bundle;
    try {
        ds >> bundle;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !bundle.IsValid()) return std::nullopt;
    return bundle;
}

uint256 ComputeBridgeVerificationBundleHash(const BridgeVerificationBundle& bundle)
{
    const auto bytes = SerializeBridgeVerificationBundle(bundle);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Verification_Bundle_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::optional<BridgeBatchAggregateCommitment> BuildDefaultBridgeBatchAggregateCommitment(
    const uint256& batch_root,
    const uint256& data_root,
    const BridgeProofPolicyCommitment& proof_policy)
{
    if (batch_root.IsNull() || data_root.IsNull()) return std::nullopt;

    BridgeBatchAggregateCommitment commitment;
    commitment.action_root = batch_root;
    commitment.data_availability_root = data_root;
    if (proof_policy.IsValid()) {
        commitment.extension_flags |= BridgeBatchAggregateCommitment::FLAG_HAS_POLICY_COMMITMENT;
        commitment.policy_commitment = proof_policy.descriptor_root;
    }
    if (!commitment.IsValid()) return std::nullopt;
    return commitment;
}

std::vector<uint8_t> SerializeBridgeBatchAggregateCommitment(const BridgeBatchAggregateCommitment& commitment)
{
    if (!commitment.IsValid()) return {};
    DataStream ds{};
    ds << commitment;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeBatchAggregateCommitment> DeserializeBridgeBatchAggregateCommitment(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeBatchAggregateCommitment commitment;
    try {
        ds >> commitment;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !commitment.IsValid()) return std::nullopt;
    return commitment;
}

uint256 ComputeBridgeBatchAggregateCommitmentHash(const BridgeBatchAggregateCommitment& commitment)
{
    const auto bytes = SerializeBridgeBatchAggregateCommitment(commitment);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_Aggregate_Commitment_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::vector<uint8_t> SerializeBridgeProofReceipt(const BridgeProofReceipt& receipt)
{
    if (!receipt.IsValid()) return {};
    DataStream ds{};
    ds << receipt;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeProofReceipt> DeserializeBridgeProofReceipt(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeProofReceipt receipt;
    try {
        ds >> receipt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !receipt.IsValid()) return std::nullopt;
    return receipt;
}

uint256 ComputeBridgeProofReceiptHash(const BridgeProofReceipt& receipt)
{
    const auto bytes = SerializeBridgeProofReceipt(receipt);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Receipt_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

uint256 ComputeBridgeProofReceiptLeafHash(const BridgeProofReceipt& receipt)
{
    const auto bytes = SerializeBridgeProofReceipt(receipt);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Receipt_Leaf_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

size_t CountDistinctBridgeProofReceipts(Span<const BridgeProofReceipt> receipts)
{
    std::set<uint256> distinct_receipts;
    for (const auto& receipt : receipts) {
        const uint256 receipt_hash = ComputeBridgeProofReceiptHash(receipt);
        if (receipt_hash.IsNull()) return 0;
        distinct_receipts.emplace(receipt_hash);
    }
    return distinct_receipts.size();
}

uint256 ComputeBridgeProofReceiptRoot(Span<const BridgeProofReceipt> receipts)
{
    if (receipts.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(receipts.size());
    for (const auto& receipt : receipts) {
        const uint256 leaf_hash = ComputeBridgeProofReceiptLeafHash(receipt);
        if (leaf_hash.IsNull()) return uint256{};
        level.push_back(leaf_hash);
    }
    std::sort(level.begin(), level.end());

    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeProofReceiptNode(left, right);
            if (parent.IsNull()) return uint256{};
            next.push_back(parent);
        }
        level = std::move(next);
    }
    return level.front();
}

std::optional<BridgeVerificationBundle> BuildBridgeVerificationBundle(Span<const BridgeBatchReceipt> receipts,
                                                                      Span<const BridgeProofReceipt> proof_receipts)
{
    if (receipts.empty() || proof_receipts.empty()) return std::nullopt;
    if (!std::all_of(receipts.begin(), receipts.end(), [](const BridgeBatchReceipt& receipt) {
            return VerifyBridgeBatchReceipt(receipt);
        })) {
        return std::nullopt;
    }
    if (!std::all_of(proof_receipts.begin(), proof_receipts.end(), [](const BridgeProofReceipt& receipt) {
            return receipt.IsValid();
        })) {
        return std::nullopt;
    }
    if (CountDistinctBridgeBatchReceiptAttestors(receipts) != receipts.size() ||
        CountDistinctBridgeProofReceipts(proof_receipts) != proof_receipts.size()) {
        return std::nullopt;
    }

    BridgeVerificationBundle bundle;
    bundle.signed_receipt_root = ComputeBridgeBatchReceiptRoot(receipts);
    bundle.proof_receipt_root = ComputeBridgeProofReceiptRoot(proof_receipts);
    if (!bundle.IsValid()) return std::nullopt;
    return bundle;
}

std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromClaim(const BridgeBatchStatement& statement,
                                                                       const BridgeProofClaim& claim)
{
    if (!statement.IsValid() || !claim.IsValid()) return std::nullopt;
    if (!DoesBridgeProofClaimMatchStatement(claim, statement)) return std::nullopt;

    const uint256 claim_hash = ComputeBridgeProofClaimHash(claim);
    if (claim_hash.IsNull()) return std::nullopt;

    BridgeExternalAnchor anchor;
    anchor.domain_id = statement.domain_id;
    anchor.source_epoch = statement.source_epoch;
    anchor.data_root = statement.data_root;
    anchor.verification_root = claim_hash;
    if (!anchor.IsValid()) return std::nullopt;
    return anchor;
}

std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromProofReceipts(const BridgeBatchStatement& statement,
                                                                               Span<const BridgeProofReceipt> receipts)
{
    if (!statement.IsValid() || receipts.empty()) return std::nullopt;
    if (statement.verifier_set.IsValid()) return std::nullopt;
    const uint256 statement_hash = ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) return std::nullopt;

    for (const auto& receipt : receipts) {
        if (!receipt.IsValid()) return std::nullopt;
        if (receipt.statement_hash != statement_hash) return std::nullopt;
    }
    if (CountDistinctBridgeProofReceipts(receipts) != receipts.size()) return std::nullopt;

    BridgeExternalAnchor anchor;
    anchor.domain_id = statement.domain_id;
    anchor.source_epoch = statement.source_epoch;
    anchor.data_root = statement.data_root;
    anchor.verification_root = ComputeBridgeProofReceiptRoot(receipts);
    if (!anchor.IsValid()) return std::nullopt;
    return anchor;
}

std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromHybridWitness(const BridgeBatchStatement& statement,
                                                                               Span<const BridgeBatchReceipt> receipts,
                                                                               Span<const BridgeProofReceipt> proof_receipts)
{
    if (!statement.IsValid() || receipts.empty() || proof_receipts.empty()) return std::nullopt;
    if (!statement.verifier_set.IsValid() || !statement.proof_policy.IsValid()) return std::nullopt;

    const uint256 statement_hash = ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) return std::nullopt;

    for (const auto& receipt : receipts) {
        if (!VerifyBridgeBatchReceipt(receipt)) return std::nullopt;
        if (ComputeBridgeBatchStatementHash(receipt.statement) != statement_hash) return std::nullopt;
    }
    if (CountDistinctBridgeBatchReceiptAttestors(receipts) != receipts.size()) return std::nullopt;

    for (const auto& receipt : proof_receipts) {
        if (!receipt.IsValid()) return std::nullopt;
        if (receipt.statement_hash != statement_hash) return std::nullopt;
    }
    const auto bundle = BuildBridgeVerificationBundle(receipts, proof_receipts);
    if (!bundle.has_value()) return std::nullopt;

    BridgeExternalAnchor anchor;
    anchor.domain_id = statement.domain_id;
    anchor.source_epoch = statement.source_epoch;
    anchor.data_root = statement.data_root;
    anchor.verification_root = ComputeBridgeVerificationBundleHash(*bundle);
    if (!anchor.IsValid()) return std::nullopt;
    return anchor;
}

std::vector<uint8_t> SerializeBridgeBatchAuthorizationMessage(const BridgeBatchAuthorization& authorization)
{
    if (!authorization.IsMessageValid()) return {};
    DataStream ds{};
    const uint8_t direction_u8 = static_cast<uint8_t>(authorization.direction);
    const uint8_t kind_u8 = static_cast<uint8_t>(authorization.kind);
    ds << authorization.version;
    ds << direction_u8;
    ds << authorization.ids;
    ds << kind_u8;
    ds << authorization.wallet_id;
    ds << authorization.destination_id;
    ds << authorization.amount;
    ds << authorization.authorization_nonce;
    ds << authorization.authorizer;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::vector<uint8_t> SerializeBridgeBatchAuthorization(const BridgeBatchAuthorization& authorization)
{
    if (!authorization.IsValid()) return {};
    DataStream ds{};
    ds << authorization;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeBatchAuthorization> DeserializeBridgeBatchAuthorization(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeBatchAuthorization authorization;
    try {
        ds >> authorization;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !authorization.IsValid()) return std::nullopt;
    return authorization;
}

uint256 ComputeBridgeBatchAuthorizationHash(const BridgeBatchAuthorization& authorization)
{
    const auto bytes = SerializeBridgeBatchAuthorizationMessage(authorization);
    if (bytes.empty()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_Authorization_V1"};
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

bool VerifyBridgeBatchAuthorization(const BridgeBatchAuthorization& authorization)
{
    if (!authorization.IsMessageValid() || !authorization.HasSignature()) return false;
    const uint256 hash = ComputeBridgeBatchAuthorizationHash(authorization);
    if (hash.IsNull()) return false;
    return CPQPubKey{authorization.authorizer.algo, authorization.authorizer.pubkey}.Verify(hash, authorization.signature);
}

bool UseBridgeBatchLeafTaggingAtHeight(int32_t height)
{
    return Params().GetConsensus().IsShieldedMatRiCTDisabled(height);
}

uint256 ComputeBridgeBatchLeafWalletTag(const BridgeBatchAuthorization& authorization,
                                        int32_t height)
{
    if (!UseBridgeBatchLeafTaggingAtHeight(height)) {
        return authorization.wallet_id;
    }

    const uint256 authorization_hash = ComputeBridgeBatchAuthorizationHash(authorization);
    if (authorization_hash.IsNull()) return uint256{};

    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_WalletTag_V2"}
       << authorization_hash
       << authorization.wallet_id;
    return hw.GetSHA256();
}

uint256 ComputeBridgeBatchLeafDestinationTag(const BridgeBatchAuthorization& authorization,
                                             int32_t height)
{
    if (!UseBridgeBatchLeafTaggingAtHeight(height)) {
        return authorization.destination_id;
    }

    const uint256 authorization_hash = ComputeBridgeBatchAuthorizationHash(authorization);
    if (authorization_hash.IsNull()) return uint256{};

    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_DestinationTag_V2"}
       << authorization_hash
       << authorization.destination_id;
    return hw.GetSHA256();
}

std::optional<BridgeBatchLeaf> BuildBridgeBatchLeafFromAuthorization(const BridgeBatchAuthorization& authorization,
                                                                     int32_t height)
{
    if (!VerifyBridgeBatchAuthorization(authorization)) return std::nullopt;
    const uint256 authorization_hash = ComputeBridgeBatchAuthorizationHash(authorization);
    if (authorization_hash.IsNull()) return std::nullopt;
    BridgeBatchLeaf leaf;
    leaf.kind = authorization.kind;
    leaf.wallet_id = ComputeBridgeBatchLeafWalletTag(authorization, height);
    leaf.destination_id = ComputeBridgeBatchLeafDestinationTag(authorization, height);
    leaf.amount = authorization.amount;
    leaf.authorization_hash = authorization_hash;
    if (!leaf.IsValid()) return std::nullopt;
    return leaf;
}

std::optional<BridgeBatchLeaf> BuildBridgeBatchLeafFromAuthorization(const BridgeBatchAuthorization& authorization)
{
    return BuildBridgeBatchLeafFromAuthorization(authorization, /*height=*/-1);
}

std::vector<uint8_t> SerializeBridgeBatchCommitment(const BridgeBatchCommitment& commitment)
{
    if (!commitment.IsValid()) return {};
    DataStream ds{};
    ds << commitment;
    const auto bytes = MakeUCharSpan(ds);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

std::optional<BridgeBatchCommitment> DeserializeBridgeBatchCommitment(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    DataStream ds{bytes};
    BridgeBatchCommitment commitment;
    try {
        ds >> commitment;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !commitment.IsValid()) return std::nullopt;
    return commitment;
}

uint256 ComputeBridgeBatchLeafHash(const BridgeBatchLeaf& leaf)
{
    if (!leaf.IsValid()) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Batch_Leaf_V1"};
    hw << leaf;
    return hw.GetSHA256();
}

uint256 ComputeBridgeBatchRoot(Span<const BridgeBatchLeaf> leaves)
{
    if (leaves.empty()) return uint256{};

    std::vector<uint256> level;
    level.reserve(leaves.size());
    for (const auto& leaf : leaves) {
        const uint256 leaf_hash = ComputeBridgeBatchLeafHash(leaf);
        if (leaf_hash.IsNull()) return uint256{};
        level.push_back(leaf_hash);
    }

    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& left = level[i];
            const uint256& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            const uint256 parent = HashBridgeBatchNode(left, right);
            if (parent.IsNull()) return uint256{};
            next.push_back(parent);
        }
        level = std::move(next);
    }
    return level.front();
}

uint256 ComputeBridgeBatchCommitmentHash(const BridgeBatchCommitment& commitment)
{
    const auto bytes = SerializeBridgeBatchCommitment(commitment);
    if (bytes.empty()) return uint256{};
    HashWriter hw = HASHER_CSFS;
    hw.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hw.GetSHA256();
}

std::vector<uint8_t> SerializeBridgeAttestationMessage(const BridgeAttestationMessage& message)
{
    if (!IsWellFormedBridgeAttestation(message)) return {};

    std::vector<uint8_t> out;
    out.reserve(1 + 32 + 1 + 32 + 32 + 32 + 4 + 4 + 8 + 32 + 1 + 32 + 4 + 32 + 32);
    out.push_back(message.version);
    out.insert(out.end(), message.genesis_hash.begin(), message.genesis_hash.end());
    out.push_back(static_cast<uint8_t>(message.direction));
    out.insert(out.end(), message.ids.bridge_id.begin(), message.ids.bridge_id.end());
    out.insert(out.end(), message.ids.operation_id.begin(), message.ids.operation_id.end());
    out.insert(out.end(), message.ctv_hash.begin(), message.ctv_hash.end());
    const uint32_t refund_lock_height = message.refund_lock_height;
    out.push_back(refund_lock_height & 0xff);
    out.push_back((refund_lock_height >> 8) & 0xff);
    out.push_back((refund_lock_height >> 16) & 0xff);
    out.push_back((refund_lock_height >> 24) & 0xff);
    if (message.version >= 2) {
        const uint32_t batch_entry_count = message.batch_entry_count;
        out.push_back(batch_entry_count & 0xff);
        out.push_back((batch_entry_count >> 8) & 0xff);
        out.push_back((batch_entry_count >> 16) & 0xff);
        out.push_back((batch_entry_count >> 24) & 0xff);

        const uint64_t total_amount = static_cast<uint64_t>(message.batch_total_amount);
        for (size_t i = 0; i < sizeof(total_amount); ++i) {
            out.push_back((total_amount >> (8 * i)) & 0xff);
        }
        out.insert(out.end(), message.batch_root.begin(), message.batch_root.end());
    }
    if (message.version >= 3) {
        out.push_back(message.external_anchor.version);
        out.insert(out.end(), message.external_anchor.domain_id.begin(), message.external_anchor.domain_id.end());
        const uint32_t source_epoch = message.external_anchor.source_epoch;
        out.push_back(source_epoch & 0xff);
        out.push_back((source_epoch >> 8) & 0xff);
        out.push_back((source_epoch >> 16) & 0xff);
        out.push_back((source_epoch >> 24) & 0xff);
        out.insert(out.end(), message.external_anchor.data_root.begin(), message.external_anchor.data_root.end());
        out.insert(out.end(), message.external_anchor.verification_root.begin(), message.external_anchor.verification_root.end());
    }
    return out;
}

std::optional<BridgeAttestationMessage> DeserializeBridgeAttestationMessage(Span<const uint8_t> bytes)
{
    static constexpr size_t MESSAGE_SIZE_V1{1 + 32 + 1 + 32 + 32 + 32 + 4};
    static constexpr size_t MESSAGE_SIZE_V2{MESSAGE_SIZE_V1 + 4 + 8 + 32};
    static constexpr size_t MESSAGE_SIZE_V3{MESSAGE_SIZE_V2 + 1 + 32 + 4 + 32 + 32};
    if (bytes.size() != MESSAGE_SIZE_V1 &&
        bytes.size() != MESSAGE_SIZE_V2 &&
        bytes.size() != MESSAGE_SIZE_V3) return std::nullopt;

    BridgeAttestationMessage message;
    size_t offset{0};
    message.version = bytes[offset++];
    std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.genesis_hash.begin());
    offset += 32;
    message.direction = static_cast<BridgeDirection>(bytes[offset++]);
    std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.ids.bridge_id.begin());
    offset += 32;
    std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.ids.operation_id.begin());
    offset += 32;
    std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.ctv_hash.begin());
    offset += 32;
    message.refund_lock_height = static_cast<uint32_t>(bytes[offset]) |
                                 (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
                                 (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
                                 (static_cast<uint32_t>(bytes[offset + 3]) << 24);
    offset += 4;
    if (message.version >= 2) {
        if (message.version == 2 && bytes.size() != MESSAGE_SIZE_V2) return std::nullopt;
        if (message.version == 3 && bytes.size() != MESSAGE_SIZE_V3) return std::nullopt;
        if (message.version > 3) return std::nullopt;
        message.batch_entry_count = static_cast<uint32_t>(bytes[offset]) |
                                    (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
                                    (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
                                    (static_cast<uint32_t>(bytes[offset + 3]) << 24);
        offset += 4;

        uint64_t total_amount{0};
        for (size_t i = 0; i < sizeof(total_amount); ++i) {
            total_amount |= static_cast<uint64_t>(bytes[offset + i]) << (8 * i);
        }
        message.batch_total_amount = static_cast<CAmount>(total_amount);
        offset += sizeof(total_amount);

        std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.batch_root.begin());
        offset += 32;
        if (message.version >= 3) {
            message.external_anchor.version = bytes[offset++];
            std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.external_anchor.domain_id.begin());
            offset += 32;
            message.external_anchor.source_epoch = static_cast<uint32_t>(bytes[offset]) |
                                                   (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
                                                   (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
                                                   (static_cast<uint32_t>(bytes[offset + 3]) << 24);
            offset += 4;
            std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.external_anchor.data_root.begin());
            offset += 32;
            std::copy(bytes.begin() + offset, bytes.begin() + offset + 32, message.external_anchor.verification_root.begin());
            offset += 32;
        }
    } else if (bytes.size() != MESSAGE_SIZE_V1) {
        return std::nullopt;
    }
    if (!IsWellFormedBridgeAttestation(message)) return std::nullopt;
    return message;
}

uint256 ComputeBridgeAttestationHash(const BridgeAttestationMessage& message)
{
    const std::vector<uint8_t> bytes = SerializeBridgeAttestationMessage(message);
    if (bytes.empty()) return uint256{};
    HashWriter hasher = HASHER_CSFS;
    hasher.write(AsBytes(Span<const uint8_t>{bytes.data(), bytes.size()}));
    return hasher.GetSHA256();
}

std::optional<BridgeScriptTree> BuildShieldBridgeScriptTree(const uint256& ctv_hash,
                                                            const BridgeKeySpec& normal_key,
                                                            uint32_t refund_lock_height,
                                                            const BridgeKeySpec& refund_key)
{
    if (ctv_hash.IsNull()) return std::nullopt;
    return BuildBridgeTreeCommon(BridgeTemplateKind::SHIELD,
                                 normal_key,
                                 refund_lock_height,
                                 refund_key,
                                 BuildP2MRCTVChecksigScript(ctv_hash, normal_key.algo, normal_key.pubkey));
}

std::optional<BridgeScriptTree> BuildUnshieldBridgeScriptTree(const uint256& ctv_hash,
                                                              const BridgeKeySpec& attestation_key,
                                                              uint32_t refund_lock_height,
                                                              const BridgeKeySpec& refund_key)
{
    if (ctv_hash.IsNull()) return std::nullopt;
    return BuildBridgeTreeCommon(BridgeTemplateKind::UNSHIELD,
                                 attestation_key,
                                 refund_lock_height,
                                 refund_key,
                                 BuildP2MRCTVCSFSScript(ctv_hash, attestation_key.algo, attestation_key.pubkey));
}

} // namespace shielded
