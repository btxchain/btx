// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_SHIELDED_BRIDGE_H
#define BTX_SHIELDED_BRIDGE_H

#include <consensus/amount.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace shielded {

enum class BridgeDirection : uint8_t {
    BRIDGE_IN = 1,
    BRIDGE_OUT = 2,
};

enum class BridgeTemplateKind : uint8_t {
    SHIELD = 1,
    UNSHIELD = 2,
};

enum class BridgeBatchLeafKind : uint8_t {
    SHIELD_CREDIT = 1,
    TRANSPARENT_PAYOUT = 2,
    SHIELDED_PAYOUT = 3,
};

enum class BridgeProofClaimKind : uint8_t {
    BATCH_TUPLE = 1,
    SETTLEMENT_METADATA = 2,
    DATA_ROOT_TUPLE = 3,
};

struct BridgeKeySpec
{
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    std::vector<unsigned char> pubkey;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t algo_u8 = static_cast<uint8_t>(algo);
        ::Serialize(s, algo_u8);
        ::Serialize(s, pubkey);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t algo_u8{0};
        ::Unserialize(s, algo_u8);
        algo = static_cast<PQAlgorithm>(algo_u8);
        ::Unserialize(s, pubkey);
    }
};

struct BridgePlanIds
{
    uint256 bridge_id;
    uint256 operation_id;

    [[nodiscard]] bool IsValid() const;

    SERIALIZE_METHODS(BridgePlanIds, obj)
    {
        READWRITE(obj.bridge_id, obj.operation_id);
    }
};

struct BridgeBatchLeaf
{
    BridgeBatchLeafKind kind{BridgeBatchLeafKind::SHIELD_CREDIT};
    uint256 wallet_id;
    uint256 destination_id;
    CAmount amount{0};
    uint256 authorization_hash;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t kind_u8 = static_cast<uint8_t>(kind);
        ::Serialize(s, kind_u8);
        ::Serialize(s, wallet_id);
        ::Serialize(s, destination_id);
        ::Serialize(s, amount);
        ::Serialize(s, authorization_hash);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t kind_u8{0};
        ::Unserialize(s, kind_u8);
        kind = static_cast<BridgeBatchLeafKind>(kind_u8);
        ::Unserialize(s, wallet_id);
        ::Unserialize(s, destination_id);
        ::Unserialize(s, amount);
        ::Unserialize(s, authorization_hash);
    }
};

struct BridgeExternalAnchor
{
    uint8_t version{1};
    uint256 domain_id;
    uint32_t source_epoch{0};
    uint256 data_root;
    uint256 verification_root;

    [[nodiscard]] bool IsEmpty() const;
    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, domain_id);
        ::Serialize(s, source_epoch);
        ::Serialize(s, data_root);
        ::Serialize(s, verification_root);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, domain_id);
        ::Unserialize(s, source_epoch);
        ::Unserialize(s, data_root);
        ::Unserialize(s, verification_root);
    }
};

struct BridgeVerifierSetCommitment
{
    uint8_t version{1};
    uint32_t attestor_count{0};
    uint32_t required_signers{0};
    uint256 attestor_root;

    [[nodiscard]] bool IsEmpty() const;
    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, attestor_count);
        ::Serialize(s, required_signers);
        ::Serialize(s, attestor_root);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, attestor_count);
        ::Unserialize(s, required_signers);
        ::Unserialize(s, attestor_root);
    }
};

struct BridgeVerifierSetProof
{
    uint8_t version{1};
    uint32_t leaf_index{0};
    std::vector<uint256> siblings;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, leaf_index);
        ::Serialize(s, siblings);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, leaf_index);
        ::Unserialize(s, siblings);
    }
};

struct BridgeProofSystemProfile
{
    uint8_t version{1};
    uint256 family_id;
    uint256 proof_type_id;
    uint256 claim_system_id;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, family_id);
        ::Serialize(s, proof_type_id);
        ::Serialize(s, claim_system_id);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, family_id);
        ::Unserialize(s, proof_type_id);
        ::Unserialize(s, claim_system_id);
    }
};

struct BridgeProofClaim
{
    uint8_t version{1};
    BridgeProofClaimKind kind{BridgeProofClaimKind::BATCH_TUPLE};
    uint256 statement_hash;
    BridgeDirection direction{BridgeDirection::BRIDGE_IN};
    BridgePlanIds ids;
    uint32_t entry_count{0};
    CAmount total_amount{0};
    uint256 batch_root;
    uint256 domain_id;
    uint32_t source_epoch{0};
    uint256 data_root;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t kind_u8 = static_cast<uint8_t>(kind);
        const uint8_t direction_u8 = static_cast<uint8_t>(direction);
        ::Serialize(s, version);
        ::Serialize(s, kind_u8);
        ::Serialize(s, statement_hash);
        ::Serialize(s, direction_u8);
        ::Serialize(s, ids);
        ::Serialize(s, entry_count);
        ::Serialize(s, total_amount);
        ::Serialize(s, batch_root);
        ::Serialize(s, domain_id);
        ::Serialize(s, source_epoch);
        ::Serialize(s, data_root);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t kind_u8{0};
        uint8_t direction_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, kind_u8);
        kind = static_cast<BridgeProofClaimKind>(kind_u8);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, direction_u8);
        direction = static_cast<BridgeDirection>(direction_u8);
        ::Unserialize(s, ids);
        ::Unserialize(s, entry_count);
        ::Unserialize(s, total_amount);
        ::Unserialize(s, batch_root);
        ::Unserialize(s, domain_id);
        ::Unserialize(s, source_epoch);
        ::Unserialize(s, data_root);
    }
};

struct BridgeProofAdapter
{
    uint8_t version{1};
    BridgeProofSystemProfile profile;
    BridgeProofClaimKind claim_kind{BridgeProofClaimKind::BATCH_TUPLE};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t claim_kind_u8 = static_cast<uint8_t>(claim_kind);
        ::Serialize(s, version);
        ::Serialize(s, profile);
        ::Serialize(s, claim_kind_u8);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t claim_kind_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, profile);
        ::Unserialize(s, claim_kind_u8);
        claim_kind = static_cast<BridgeProofClaimKind>(claim_kind_u8);
    }
};

struct BridgeProofArtifact
{
    uint8_t version{1};
    BridgeProofAdapter adapter;
    uint256 statement_hash;
    uint256 verifier_key_hash;
    uint256 public_values_hash;
    uint256 proof_commitment;
    uint256 artifact_commitment;
    uint32_t proof_size_bytes{0};
    uint32_t public_values_size_bytes{0};
    uint32_t auxiliary_data_size_bytes{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, adapter);
        ::Serialize(s, statement_hash);
        ::Serialize(s, verifier_key_hash);
        ::Serialize(s, public_values_hash);
        ::Serialize(s, proof_commitment);
        ::Serialize(s, artifact_commitment);
        ::Serialize(s, proof_size_bytes);
        ::Serialize(s, public_values_size_bytes);
        ::Serialize(s, auxiliary_data_size_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, adapter);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, verifier_key_hash);
        ::Unserialize(s, public_values_hash);
        ::Unserialize(s, proof_commitment);
        ::Unserialize(s, artifact_commitment);
        ::Unserialize(s, proof_size_bytes);
        ::Unserialize(s, public_values_size_bytes);
        ::Unserialize(s, auxiliary_data_size_bytes);
    }
};

enum class BridgeDataArtifactKind : uint8_t {
    STATE_DIFF = 0,
    SNAPSHOT_APPENDIX = 1,
    DATA_ROOT_QUERY = 2,
};

struct BridgeDataArtifact
{
    uint8_t version{1};
    BridgeDataArtifactKind kind{BridgeDataArtifactKind::STATE_DIFF};
    uint256 statement_hash;
    uint256 data_root;
    uint256 payload_commitment;
    uint256 artifact_commitment;
    uint32_t payload_size_bytes{0};
    uint32_t auxiliary_data_size_bytes{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t kind_u8 = static_cast<uint8_t>(kind);
        ::Serialize(s, version);
        ::Serialize(s, kind_u8);
        ::Serialize(s, statement_hash);
        ::Serialize(s, data_root);
        ::Serialize(s, payload_commitment);
        ::Serialize(s, artifact_commitment);
        ::Serialize(s, payload_size_bytes);
        ::Serialize(s, auxiliary_data_size_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t kind_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, kind_u8);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, data_root);
        ::Unserialize(s, payload_commitment);
        ::Unserialize(s, artifact_commitment);
        ::Unserialize(s, payload_size_bytes);
        ::Unserialize(s, auxiliary_data_size_bytes);
        kind = static_cast<BridgeDataArtifactKind>(kind_u8);
    }
};

struct BridgeAggregateArtifactBundle
{
    uint8_t version{1};
    uint256 statement_hash;
    uint256 proof_artifact_root;
    uint256 data_artifact_root;
    uint32_t proof_artifact_count{0};
    uint32_t data_artifact_count{0};
    uint64_t proof_payload_bytes{0};
    uint64_t proof_auxiliary_bytes{0};
    uint64_t data_availability_payload_bytes{0};
    uint64_t data_auxiliary_bytes{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, statement_hash);
        ::Serialize(s, proof_artifact_root);
        ::Serialize(s, data_artifact_root);
        ::Serialize(s, proof_artifact_count);
        ::Serialize(s, data_artifact_count);
        ::Serialize(s, proof_payload_bytes);
        ::Serialize(s, proof_auxiliary_bytes);
        ::Serialize(s, data_availability_payload_bytes);
        ::Serialize(s, data_auxiliary_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, proof_artifact_root);
        ::Unserialize(s, data_artifact_root);
        ::Unserialize(s, proof_artifact_count);
        ::Unserialize(s, data_artifact_count);
        ::Unserialize(s, proof_payload_bytes);
        ::Unserialize(s, proof_auxiliary_bytes);
        ::Unserialize(s, data_availability_payload_bytes);
        ::Unserialize(s, data_auxiliary_bytes);
    }
};

enum class BridgeAggregatePayloadLocation : uint8_t {
    INLINE_NON_WITNESS = 0,
    INLINE_WITNESS = 1,
    L1_DATA_AVAILABILITY = 2,
    OFFCHAIN = 3,
};

struct BridgeAggregateSettlement
{
    uint8_t version{1};
    uint256 statement_hash;
    uint32_t batched_user_count{0};
    uint32_t new_wallet_count{0};
    uint32_t input_count{0};
    uint32_t output_count{0};
    uint64_t base_non_witness_bytes{0};
    uint64_t base_witness_bytes{0};
    uint64_t state_commitment_bytes{0};
    uint64_t proof_payload_bytes{0};
    uint64_t data_availability_payload_bytes{0};
    uint64_t control_plane_bytes{0};
    uint64_t auxiliary_offchain_bytes{0};
    BridgeAggregatePayloadLocation proof_payload_location{BridgeAggregatePayloadLocation::INLINE_WITNESS};
    BridgeAggregatePayloadLocation data_availability_location{BridgeAggregatePayloadLocation::OFFCHAIN};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t proof_location_u8 = static_cast<uint8_t>(proof_payload_location);
        const uint8_t data_location_u8 = static_cast<uint8_t>(data_availability_location);
        ::Serialize(s, version);
        ::Serialize(s, statement_hash);
        ::Serialize(s, batched_user_count);
        ::Serialize(s, new_wallet_count);
        ::Serialize(s, input_count);
        ::Serialize(s, output_count);
        ::Serialize(s, base_non_witness_bytes);
        ::Serialize(s, base_witness_bytes);
        ::Serialize(s, state_commitment_bytes);
        ::Serialize(s, proof_payload_bytes);
        ::Serialize(s, data_availability_payload_bytes);
        ::Serialize(s, control_plane_bytes);
        ::Serialize(s, auxiliary_offchain_bytes);
        ::Serialize(s, proof_location_u8);
        ::Serialize(s, data_location_u8);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t proof_location_u8{0};
        uint8_t data_location_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, batched_user_count);
        ::Unserialize(s, new_wallet_count);
        ::Unserialize(s, input_count);
        ::Unserialize(s, output_count);
        ::Unserialize(s, base_non_witness_bytes);
        ::Unserialize(s, base_witness_bytes);
        ::Unserialize(s, state_commitment_bytes);
        ::Unserialize(s, proof_payload_bytes);
        ::Unserialize(s, data_availability_payload_bytes);
        ::Unserialize(s, control_plane_bytes);
        ::Unserialize(s, auxiliary_offchain_bytes);
        ::Unserialize(s, proof_location_u8);
        ::Unserialize(s, data_location_u8);
        proof_payload_location = static_cast<BridgeAggregatePayloadLocation>(proof_location_u8);
        data_availability_location = static_cast<BridgeAggregatePayloadLocation>(data_location_u8);
    }
};

enum class BridgeCapacityBinding : uint8_t {
    TIED = 0,
    SERIALIZED_SIZE = 1,
    WEIGHT = 2,
    DATA_AVAILABILITY = 3,
};

enum class BridgeThroughputBinding : uint8_t {
    TIED = 0,
    L1 = 1,
    PROVER = 2,
};

struct BridgeCapacityFootprint
{
    uint64_t l1_serialized_bytes{0};
    uint64_t l1_weight{0};
    uint64_t l1_data_availability_bytes{0};
    uint64_t control_plane_bytes{0};
    uint64_t offchain_storage_bytes{0};
    uint32_t batched_user_count{1};

    [[nodiscard]] bool IsValid() const;
};

struct BridgeCapacityEstimate
{
    BridgeCapacityFootprint footprint;
    uint64_t block_serialized_limit{0};
    uint64_t block_weight_limit{0};
    std::optional<uint64_t> block_data_availability_limit;
    uint64_t fit_by_serialized_size{0};
    uint64_t fit_by_weight{0};
    std::optional<uint64_t> fit_by_data_availability;
    BridgeCapacityBinding binding_limit{BridgeCapacityBinding::TIED};
    uint64_t max_settlements_per_block{0};
    uint64_t users_per_block{0};
    uint64_t total_l1_serialized_bytes{0};
    uint64_t total_l1_weight{0};
    uint64_t total_l1_data_availability_bytes{0};
    uint64_t total_control_plane_bytes{0};
    uint64_t total_offchain_storage_bytes{0};
};

struct BridgeProofCompressionTarget
{
    uint8_t version{1};
    uint256 settlement_id;
    uint256 statement_hash;
    uint64_t block_serialized_limit{0};
    uint64_t block_weight_limit{0};
    uint64_t block_data_availability_limit{0};
    uint64_t target_users_per_block{0};
    uint64_t target_settlements_per_block{0};
    uint32_t batched_user_count{0};
    uint32_t proof_artifact_count{0};
    uint64_t current_proof_payload_bytes{0};
    uint64_t current_proof_auxiliary_bytes{0};
    uint64_t fixed_l1_serialized_bytes{0};
    uint64_t fixed_l1_weight{0};
    uint64_t fixed_l1_data_availability_bytes{0};
    uint64_t fixed_control_plane_bytes{0};
    uint64_t fixed_offchain_storage_bytes{0};
    BridgeAggregatePayloadLocation proof_payload_location{BridgeAggregatePayloadLocation::INLINE_WITNESS};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t proof_location_u8 = static_cast<uint8_t>(proof_payload_location);
        ::Serialize(s, version);
        ::Serialize(s, settlement_id);
        ::Serialize(s, statement_hash);
        ::Serialize(s, block_serialized_limit);
        ::Serialize(s, block_weight_limit);
        ::Serialize(s, block_data_availability_limit);
        ::Serialize(s, target_users_per_block);
        ::Serialize(s, target_settlements_per_block);
        ::Serialize(s, batched_user_count);
        ::Serialize(s, proof_artifact_count);
        ::Serialize(s, current_proof_payload_bytes);
        ::Serialize(s, current_proof_auxiliary_bytes);
        ::Serialize(s, fixed_l1_serialized_bytes);
        ::Serialize(s, fixed_l1_weight);
        ::Serialize(s, fixed_l1_data_availability_bytes);
        ::Serialize(s, fixed_control_plane_bytes);
        ::Serialize(s, fixed_offchain_storage_bytes);
        ::Serialize(s, proof_location_u8);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t proof_location_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, settlement_id);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, block_serialized_limit);
        ::Unserialize(s, block_weight_limit);
        ::Unserialize(s, block_data_availability_limit);
        ::Unserialize(s, target_users_per_block);
        ::Unserialize(s, target_settlements_per_block);
        ::Unserialize(s, batched_user_count);
        ::Unserialize(s, proof_artifact_count);
        ::Unserialize(s, current_proof_payload_bytes);
        ::Unserialize(s, current_proof_auxiliary_bytes);
        ::Unserialize(s, fixed_l1_serialized_bytes);
        ::Unserialize(s, fixed_l1_weight);
        ::Unserialize(s, fixed_l1_data_availability_bytes);
        ::Unserialize(s, fixed_control_plane_bytes);
        ::Unserialize(s, fixed_offchain_storage_bytes);
        ::Unserialize(s, proof_location_u8);
        proof_payload_location = static_cast<BridgeAggregatePayloadLocation>(proof_location_u8);
    }
};

struct BridgeProofCompressionEstimate
{
    BridgeProofCompressionTarget target;
    BridgeCapacityEstimate current_capacity;
    BridgeCapacityEstimate zero_proof_capacity;
    bool achievable{false};
    BridgeCapacityBinding target_binding_limit{BridgeCapacityBinding::TIED};
    std::optional<uint64_t> max_proof_payload_bytes_by_serialized_size;
    std::optional<uint64_t> max_proof_payload_bytes_by_weight;
    std::optional<uint64_t> max_proof_payload_bytes_by_data_availability;
    std::optional<uint64_t> required_max_proof_payload_bytes;
    std::optional<uint64_t> required_proof_payload_reduction_bytes;
    std::optional<BridgeCapacityEstimate> modeled_target_capacity;
};

struct BridgeShieldedStateProfile
{
    uint8_t version{1};
    uint64_t commitment_index_key_bytes{9};
    uint64_t commitment_index_value_bytes{32};
    uint64_t snapshot_commitment_bytes{32};
    uint64_t nullifier_index_key_bytes{33};
    uint64_t nullifier_index_value_bytes{1};
    uint64_t snapshot_nullifier_bytes{32};
    uint64_t nullifier_cache_bytes{96};
    uint64_t wallet_materialization_bytes{0};
    uint64_t bounded_anchor_history_bytes{800};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, commitment_index_key_bytes);
        ::Serialize(s, commitment_index_value_bytes);
        ::Serialize(s, snapshot_commitment_bytes);
        ::Serialize(s, nullifier_index_key_bytes);
        ::Serialize(s, nullifier_index_value_bytes);
        ::Serialize(s, snapshot_nullifier_bytes);
        ::Serialize(s, nullifier_cache_bytes);
        ::Serialize(s, wallet_materialization_bytes);
        ::Serialize(s, bounded_anchor_history_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, commitment_index_key_bytes);
        ::Unserialize(s, commitment_index_value_bytes);
        ::Unserialize(s, snapshot_commitment_bytes);
        ::Unserialize(s, nullifier_index_key_bytes);
        ::Unserialize(s, nullifier_index_value_bytes);
        ::Unserialize(s, snapshot_nullifier_bytes);
        ::Unserialize(s, nullifier_cache_bytes);
        ::Unserialize(s, wallet_materialization_bytes);
        ::Unserialize(s, bounded_anchor_history_bytes);
    }
};

struct BridgeShieldedStateEstimate
{
    BridgeAggregateSettlement settlement;
    BridgeShieldedStateProfile profile;
    BridgeCapacityEstimate capacity;
    uint64_t block_interval_millis{0};
    uint64_t note_commitments_per_settlement{0};
    uint64_t nullifiers_per_settlement{0};
    uint64_t new_wallets_per_settlement{0};
    uint64_t commitment_index_bytes_per_settlement{0};
    uint64_t nullifier_index_bytes_per_settlement{0};
    uint64_t snapshot_appendix_bytes_per_settlement{0};
    uint64_t wallet_materialization_bytes_per_settlement{0};
    uint64_t persistent_state_bytes_per_settlement{0};
    uint64_t hot_cache_bytes_per_settlement{0};
    uint64_t bounded_state_bytes{0};
    uint64_t note_commitments_per_block{0};
    uint64_t nullifiers_per_block{0};
    uint64_t new_wallets_per_block{0};
    uint64_t persistent_state_bytes_per_block{0};
    uint64_t snapshot_appendix_bytes_per_block{0};
    uint64_t hot_cache_bytes_per_block{0};
    uint64_t note_commitments_per_hour{0};
    uint64_t nullifiers_per_hour{0};
    uint64_t new_wallets_per_hour{0};
    uint64_t persistent_state_bytes_per_hour{0};
    uint64_t snapshot_appendix_bytes_per_hour{0};
    uint64_t hot_cache_bytes_per_hour{0};
    uint64_t persistent_state_bytes_per_day{0};
    uint64_t snapshot_appendix_bytes_per_day{0};
    uint64_t hot_cache_bytes_per_day{0};
};

struct BridgeShieldedStateRetentionPolicy
{
    // Production uses the externalized-retention posture and targets weekly
    // snapshot exports that stay below the modeled ~4 GiB operational envelope.
    inline static constexpr uint32_t PRODUCTION_WALLET_L1_MATERIALIZATION_BPS{2'500};
    inline static constexpr uint64_t WEEKLY_SNAPSHOT_TARGET_BYTES{2'642'412'320ULL};

    uint8_t version{1};
    bool retain_commitment_index{false};
    bool retain_nullifier_index{true};
    bool snapshot_include_commitments{false};
    bool snapshot_include_nullifiers{true};
    uint32_t wallet_l1_materialization_bps{PRODUCTION_WALLET_L1_MATERIALIZATION_BPS};
    uint64_t snapshot_target_bytes{WEEKLY_SNAPSHOT_TARGET_BYTES};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, retain_commitment_index);
        ::Serialize(s, retain_nullifier_index);
        ::Serialize(s, snapshot_include_commitments);
        ::Serialize(s, snapshot_include_nullifiers);
        ::Serialize(s, wallet_l1_materialization_bps);
        ::Serialize(s, snapshot_target_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, retain_commitment_index);
        ::Unserialize(s, retain_nullifier_index);
        ::Unserialize(s, snapshot_include_commitments);
        ::Unserialize(s, snapshot_include_nullifiers);
        ::Unserialize(s, wallet_l1_materialization_bps);
        ::Unserialize(s, snapshot_target_bytes);
    }
};

struct BridgeShieldedStateRetentionEstimate
{
    BridgeShieldedStateEstimate state;
    BridgeShieldedStateRetentionPolicy policy;
    uint64_t materialized_wallets_per_settlement{0};
    uint64_t deferred_wallets_per_settlement{0};
    uint64_t retained_persistent_state_bytes_per_settlement{0};
    uint64_t externalized_persistent_state_bytes_per_settlement{0};
    uint64_t deferred_wallet_materialization_bytes_per_settlement{0};
    uint64_t snapshot_export_bytes_per_settlement{0};
    uint64_t externalized_snapshot_bytes_per_settlement{0};
    uint64_t runtime_hot_cache_bytes_per_settlement{0};
    uint64_t bounded_snapshot_bytes{0};
    uint64_t retained_persistent_state_bytes_per_block{0};
    uint64_t externalized_persistent_state_bytes_per_block{0};
    uint64_t deferred_wallet_materialization_bytes_per_block{0};
    uint64_t snapshot_export_bytes_per_block{0};
    uint64_t externalized_snapshot_bytes_per_block{0};
    uint64_t runtime_hot_cache_bytes_per_block{0};
    uint64_t retained_persistent_state_bytes_per_hour{0};
    uint64_t externalized_persistent_state_bytes_per_hour{0};
    uint64_t deferred_wallet_materialization_bytes_per_hour{0};
    uint64_t snapshot_export_bytes_per_hour{0};
    uint64_t externalized_snapshot_bytes_per_hour{0};
    uint64_t runtime_hot_cache_bytes_per_hour{0};
    uint64_t retained_persistent_state_bytes_per_day{0};
    uint64_t externalized_persistent_state_bytes_per_day{0};
    uint64_t deferred_wallet_materialization_bytes_per_day{0};
    uint64_t snapshot_export_bytes_per_day{0};
    uint64_t externalized_snapshot_bytes_per_day{0};
    uint64_t runtime_hot_cache_bytes_per_day{0};
    std::optional<uint64_t> blocks_to_snapshot_target;
    std::optional<uint64_t> hours_to_snapshot_target;
    std::optional<uint64_t> days_to_snapshot_target;
    std::optional<uint64_t> users_to_snapshot_target;
};

struct BridgeProverLane
{
    uint64_t millis_per_settlement{0};
    uint32_t workers{0};
    uint32_t parallel_jobs_per_worker{1};
    uint64_t hourly_cost_cents{0};

    [[nodiscard]] bool IsValid() const;
};

struct BridgeProverFootprint
{
    uint64_t block_interval_millis{0};
    std::optional<BridgeProverLane> native;
    std::optional<BridgeProverLane> cpu;
    std::optional<BridgeProverLane> gpu;
    std::optional<BridgeProverLane> network;

    [[nodiscard]] bool IsValid() const;
};

struct BridgeProverLaneEstimate
{
    BridgeProverLane lane;
    uint64_t effective_parallel_jobs{0};
    uint64_t settlements_per_block_interval{0};
    uint64_t settlements_per_hour{0};
    uint64_t users_per_block_interval{0};
    uint64_t users_per_hour{0};
    uint64_t sustainable_settlements_per_block{0};
    uint64_t sustainable_settlements_per_hour{0};
    uint64_t sustainable_users_per_block{0};
    uint64_t sustainable_users_per_hour{0};
    BridgeThroughputBinding binding_limit{BridgeThroughputBinding::TIED};
    uint64_t required_parallel_jobs_to_fill_l1_capacity{0};
    uint64_t required_workers_to_fill_l1_capacity{0};
    uint64_t worker_gap_to_fill_l1_capacity{0};
    uint64_t millis_to_fill_l1_capacity{0};
    uint64_t current_hourly_cost_cents{0};
    uint64_t required_hourly_cost_cents{0};
};

struct BridgeProverCapacityEstimate
{
    BridgeProverFootprint footprint;
    BridgeCapacityEstimate l1_capacity;
    uint64_t l1_settlements_per_hour_limit{0};
    uint64_t l1_users_per_hour_limit{0};
    std::optional<BridgeProverLaneEstimate> native;
    std::optional<BridgeProverLaneEstimate> cpu;
    std::optional<BridgeProverLaneEstimate> gpu;
    std::optional<BridgeProverLaneEstimate> network;
};

struct BridgeProverSample
{
    uint8_t version{1};
    uint256 statement_hash;
    uint256 proof_artifact_id;
    uint256 proof_system_id;
    uint256 verifier_key_hash;
    uint64_t artifact_storage_bytes{0};
    uint64_t native_millis{0};
    uint64_t cpu_millis{0};
    uint64_t gpu_millis{0};
    uint64_t network_millis{0};
    uint64_t peak_memory_bytes{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, statement_hash);
        ::Serialize(s, proof_artifact_id);
        ::Serialize(s, proof_system_id);
        ::Serialize(s, verifier_key_hash);
        ::Serialize(s, artifact_storage_bytes);
        ::Serialize(s, native_millis);
        ::Serialize(s, cpu_millis);
        ::Serialize(s, gpu_millis);
        ::Serialize(s, network_millis);
        ::Serialize(s, peak_memory_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, proof_artifact_id);
        ::Unserialize(s, proof_system_id);
        ::Unserialize(s, verifier_key_hash);
        ::Unserialize(s, artifact_storage_bytes);
        ::Unserialize(s, native_millis);
        ::Unserialize(s, cpu_millis);
        ::Unserialize(s, gpu_millis);
        ::Unserialize(s, network_millis);
        ::Unserialize(s, peak_memory_bytes);
    }
};

struct BridgeProverProfile
{
    uint8_t version{1};
    uint256 statement_hash;
    uint32_t sample_count{0};
    uint256 sample_root;
    uint64_t total_artifact_storage_bytes{0};
    uint64_t total_peak_memory_bytes{0};
    uint64_t max_peak_memory_bytes{0};
    uint64_t native_millis_per_settlement{0};
    uint64_t cpu_millis_per_settlement{0};
    uint64_t gpu_millis_per_settlement{0};
    uint64_t network_millis_per_settlement{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, statement_hash);
        ::Serialize(s, sample_count);
        ::Serialize(s, sample_root);
        ::Serialize(s, total_artifact_storage_bytes);
        ::Serialize(s, total_peak_memory_bytes);
        ::Serialize(s, max_peak_memory_bytes);
        ::Serialize(s, native_millis_per_settlement);
        ::Serialize(s, cpu_millis_per_settlement);
        ::Serialize(s, gpu_millis_per_settlement);
        ::Serialize(s, network_millis_per_settlement);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, sample_count);
        ::Unserialize(s, sample_root);
        ::Unserialize(s, total_artifact_storage_bytes);
        ::Unserialize(s, total_peak_memory_bytes);
        ::Unserialize(s, max_peak_memory_bytes);
        ::Unserialize(s, native_millis_per_settlement);
        ::Unserialize(s, cpu_millis_per_settlement);
        ::Unserialize(s, gpu_millis_per_settlement);
        ::Unserialize(s, network_millis_per_settlement);
    }
};

struct BridgeProverMetricSummary
{
    uint64_t min{0};
    uint64_t p50{0};
    uint64_t p90{0};
    uint64_t max{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, min);
        ::Serialize(s, p50);
        ::Serialize(s, p90);
        ::Serialize(s, max);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, min);
        ::Unserialize(s, p50);
        ::Unserialize(s, p90);
        ::Unserialize(s, max);
    }
};

enum class BridgeProverBenchmarkStatistic : uint8_t {
    MIN = 0,
    P50 = 1,
    P90 = 2,
    MAX = 3,
};

struct BridgeProverBenchmark
{
    uint8_t version{1};
    uint256 statement_hash;
    uint32_t profile_count{0};
    uint32_t sample_count_per_profile{0};
    uint256 profile_root;
    uint64_t artifact_storage_bytes_per_profile{0};
    BridgeProverMetricSummary total_peak_memory_bytes;
    BridgeProverMetricSummary max_peak_memory_bytes;
    BridgeProverMetricSummary native_millis_per_settlement;
    BridgeProverMetricSummary cpu_millis_per_settlement;
    BridgeProverMetricSummary gpu_millis_per_settlement;
    BridgeProverMetricSummary network_millis_per_settlement;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, statement_hash);
        ::Serialize(s, profile_count);
        ::Serialize(s, sample_count_per_profile);
        ::Serialize(s, profile_root);
        ::Serialize(s, artifact_storage_bytes_per_profile);
        ::Serialize(s, total_peak_memory_bytes);
        ::Serialize(s, max_peak_memory_bytes);
        ::Serialize(s, native_millis_per_settlement);
        ::Serialize(s, cpu_millis_per_settlement);
        ::Serialize(s, gpu_millis_per_settlement);
        ::Serialize(s, network_millis_per_settlement);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, profile_count);
        ::Unserialize(s, sample_count_per_profile);
        ::Unserialize(s, profile_root);
        ::Unserialize(s, artifact_storage_bytes_per_profile);
        ::Unserialize(s, total_peak_memory_bytes);
        ::Unserialize(s, max_peak_memory_bytes);
        ::Unserialize(s, native_millis_per_settlement);
        ::Unserialize(s, cpu_millis_per_settlement);
        ::Unserialize(s, gpu_millis_per_settlement);
        ::Unserialize(s, network_millis_per_settlement);
    }
};

struct BridgeProofDescriptor
{
    uint256 proof_system_id;
    uint256 verifier_key_hash;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, proof_system_id);
        ::Serialize(s, verifier_key_hash);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, proof_system_id);
        ::Unserialize(s, verifier_key_hash);
    }
};

struct BridgeProofPolicyCommitment
{
    uint8_t version{1};
    uint32_t descriptor_count{0};
    uint32_t required_receipts{0};
    uint256 descriptor_root;

    [[nodiscard]] bool IsEmpty() const;
    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, descriptor_count);
        ::Serialize(s, required_receipts);
        ::Serialize(s, descriptor_root);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, descriptor_count);
        ::Unserialize(s, required_receipts);
        ::Unserialize(s, descriptor_root);
    }
};

struct BridgeProofPolicyProof
{
    uint8_t version{1};
    uint32_t leaf_index{0};
    std::vector<uint256> siblings;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, leaf_index);
        ::Serialize(s, siblings);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, leaf_index);
        ::Unserialize(s, siblings);
    }
};

struct BridgeVerificationBundle
{
    uint8_t version{1};
    uint256 signed_receipt_root;
    uint256 proof_receipt_root;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, signed_receipt_root);
        ::Serialize(s, proof_receipt_root);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, signed_receipt_root);
        ::Unserialize(s, proof_receipt_root);
    }
};

struct BridgeBatchAggregateCommitment
{
    static constexpr uint32_t FLAG_HAS_RECOVERY_OR_EXIT_ROOT = 1U << 0;
    static constexpr uint32_t FLAG_HAS_POLICY_COMMITMENT = 1U << 1;
    static constexpr uint32_t FLAG_CUSTOM_ACTION_ROOT = 1U << 2;
    static constexpr uint32_t FLAG_CUSTOM_DATA_AVAILABILITY_ROOT = 1U << 3;

    uint8_t version{1};
    uint256 action_root;
    uint256 data_availability_root;
    uint256 recovery_or_exit_root;
    uint32_t extension_flags{0};
    uint256 policy_commitment;

    [[nodiscard]] bool IsEmpty() const;
    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, action_root);
        ::Serialize(s, data_availability_root);
        ::Serialize(s, recovery_or_exit_root);
        ::Serialize(s, extension_flags);
        ::Serialize(s, policy_commitment);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, action_root);
        ::Unserialize(s, data_availability_root);
        ::Unserialize(s, recovery_or_exit_root);
        ::Unserialize(s, extension_flags);
        ::Unserialize(s, policy_commitment);
    }
};

struct BridgeBatchStatement
{
    uint8_t version{1};
    BridgeDirection direction{BridgeDirection::BRIDGE_IN};
    BridgePlanIds ids;
    uint32_t entry_count{0};
    CAmount total_amount{0};
    uint256 batch_root;
    uint256 domain_id;
    uint32_t source_epoch{0};
    uint256 data_root;
    BridgeVerifierSetCommitment verifier_set;
    BridgeProofPolicyCommitment proof_policy;
    BridgeBatchAggregateCommitment aggregate_commitment;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t direction_u8 = static_cast<uint8_t>(direction);
        ::Serialize(s, version);
        ::Serialize(s, direction_u8);
        ::Serialize(s, ids);
        ::Serialize(s, entry_count);
        ::Serialize(s, total_amount);
        ::Serialize(s, batch_root);
        ::Serialize(s, domain_id);
        ::Serialize(s, source_epoch);
        ::Serialize(s, data_root);
        if (version >= 2) {
            ::Serialize(s, verifier_set);
        }
        if (version >= 3) {
            ::Serialize(s, proof_policy);
        }
        if (version >= 5) {
            ::Serialize(s, aggregate_commitment);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t direction_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, direction_u8);
        direction = static_cast<BridgeDirection>(direction_u8);
        ::Unserialize(s, ids);
        ::Unserialize(s, entry_count);
        ::Unserialize(s, total_amount);
        ::Unserialize(s, batch_root);
        ::Unserialize(s, domain_id);
        ::Unserialize(s, source_epoch);
        ::Unserialize(s, data_root);
        if (version >= 2) {
            ::Unserialize(s, verifier_set);
        }
        if (version >= 3) {
            ::Unserialize(s, proof_policy);
        }
        if (version >= 5) {
            ::Unserialize(s, aggregate_commitment);
        }
    }
};

struct BridgeBatchCommitment
{
    uint8_t version{1};
    BridgeDirection direction{BridgeDirection::BRIDGE_IN};
    BridgePlanIds ids;
    uint32_t entry_count{0};
    CAmount total_amount{0};
    uint256 batch_root;
    BridgeExternalAnchor external_anchor;
    BridgeBatchAggregateCommitment aggregate_commitment;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t direction_u8 = static_cast<uint8_t>(direction);
        ::Serialize(s, version);
        ::Serialize(s, direction_u8);
        ::Serialize(s, ids);
        ::Serialize(s, entry_count);
        ::Serialize(s, total_amount);
        ::Serialize(s, batch_root);
        if (version >= 2) {
            ::Serialize(s, external_anchor);
        }
        if (version >= 3) {
            ::Serialize(s, aggregate_commitment);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t direction_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, direction_u8);
        direction = static_cast<BridgeDirection>(direction_u8);
        ::Unserialize(s, ids);
        ::Unserialize(s, entry_count);
        ::Unserialize(s, total_amount);
        ::Unserialize(s, batch_root);
        if (version >= 2) {
            ::Unserialize(s, external_anchor);
        }
        if (version >= 3) {
            ::Unserialize(s, aggregate_commitment);
        }
    }
};

struct BridgeBatchReceipt
{
    uint8_t version{1};
    BridgeBatchStatement statement;
    BridgeKeySpec attestor;
    std::vector<unsigned char> signature;

    [[nodiscard]] bool IsMessageValid() const;
    [[nodiscard]] bool HasSignature() const;
    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, statement);
        ::Serialize(s, attestor);
        ::Serialize(s, signature);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, statement);
        ::Unserialize(s, attestor);
        ::Unserialize(s, signature);
    }
};

struct BridgeProofReceipt
{
    uint8_t version{1};
    uint256 statement_hash;
    uint256 proof_system_id;
    uint256 verifier_key_hash;
    uint256 public_values_hash;
    uint256 proof_commitment;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, version);
        ::Serialize(s, statement_hash);
        ::Serialize(s, proof_system_id);
        ::Serialize(s, verifier_key_hash);
        ::Serialize(s, public_values_hash);
        ::Serialize(s, proof_commitment);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, version);
        ::Unserialize(s, statement_hash);
        ::Unserialize(s, proof_system_id);
        ::Unserialize(s, verifier_key_hash);
        ::Unserialize(s, public_values_hash);
        ::Unserialize(s, proof_commitment);
    }
};

struct BridgeBatchAuthorization
{
    uint8_t version{1};
    BridgeDirection direction{BridgeDirection::BRIDGE_IN};
    BridgePlanIds ids;
    BridgeBatchLeafKind kind{BridgeBatchLeafKind::SHIELD_CREDIT};
    uint256 wallet_id;
    uint256 destination_id;
    CAmount amount{0};
    uint256 authorization_nonce;
    BridgeKeySpec authorizer;
    std::vector<unsigned char> signature;

    [[nodiscard]] bool IsMessageValid() const;
    [[nodiscard]] bool HasSignature() const;
    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t direction_u8 = static_cast<uint8_t>(direction);
        const uint8_t kind_u8 = static_cast<uint8_t>(kind);
        ::Serialize(s, version);
        ::Serialize(s, direction_u8);
        ::Serialize(s, ids);
        ::Serialize(s, kind_u8);
        ::Serialize(s, wallet_id);
        ::Serialize(s, destination_id);
        ::Serialize(s, amount);
        ::Serialize(s, authorization_nonce);
        ::Serialize(s, authorizer);
        ::Serialize(s, signature);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t direction_u8{0};
        uint8_t kind_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, direction_u8);
        direction = static_cast<BridgeDirection>(direction_u8);
        ::Unserialize(s, ids);
        ::Unserialize(s, kind_u8);
        kind = static_cast<BridgeBatchLeafKind>(kind_u8);
        ::Unserialize(s, wallet_id);
        ::Unserialize(s, destination_id);
        ::Unserialize(s, amount);
        ::Unserialize(s, authorization_nonce);
        ::Unserialize(s, authorizer);
        ::Unserialize(s, signature);
    }
};

struct BridgeScriptTree
{
    BridgeTemplateKind kind{BridgeTemplateKind::SHIELD};
    BridgeKeySpec normal_key;
    BridgeKeySpec refund_key;
    uint32_t refund_lock_height{0};
    uint256 merkle_root;
    uint256 normal_leaf_hash;
    uint256 refund_leaf_hash;
    std::vector<unsigned char> normal_leaf_script;
    std::vector<unsigned char> normal_control_block;
    std::vector<unsigned char> refund_leaf_script;
    std::vector<unsigned char> refund_control_block;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t kind_u8 = static_cast<uint8_t>(kind);
        ::Serialize(s, kind_u8);
        ::Serialize(s, normal_key);
        ::Serialize(s, refund_key);
        ::Serialize(s, refund_lock_height);
        ::Serialize(s, merkle_root);
        ::Serialize(s, normal_leaf_hash);
        ::Serialize(s, refund_leaf_hash);
        ::Serialize(s, normal_leaf_script);
        ::Serialize(s, normal_control_block);
        ::Serialize(s, refund_leaf_script);
        ::Serialize(s, refund_control_block);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t kind_u8{0};
        ::Unserialize(s, kind_u8);
        kind = static_cast<BridgeTemplateKind>(kind_u8);
        ::Unserialize(s, normal_key);
        ::Unserialize(s, refund_key);
        ::Unserialize(s, refund_lock_height);
        ::Unserialize(s, merkle_root);
        ::Unserialize(s, normal_leaf_hash);
        ::Unserialize(s, refund_leaf_hash);
        ::Unserialize(s, normal_leaf_script);
        ::Unserialize(s, normal_control_block);
        ::Unserialize(s, refund_leaf_script);
        ::Unserialize(s, refund_control_block);
    }
};

struct BridgeAttestationMessage
{
    uint8_t version{1};
    uint256 genesis_hash;
    BridgeDirection direction{BridgeDirection::BRIDGE_IN};
    BridgePlanIds ids;
    uint256 ctv_hash;
    uint32_t refund_lock_height{0};
    uint32_t batch_entry_count{0};
    CAmount batch_total_amount{0};
    uint256 batch_root;
    BridgeExternalAnchor external_anchor;
};

[[nodiscard]] bool IsValidBridgePubkey(PQAlgorithm algo, Span<const unsigned char> pubkey);
[[nodiscard]] bool IsValidRefundLockHeight(uint32_t refund_lock_height);
[[nodiscard]] bool IsWellFormedBridgeAttestation(const BridgeAttestationMessage& message);
[[nodiscard]] bool DoesBridgeAttestationMatchGenesis(const BridgeAttestationMessage& message, const uint256& genesis_hash);
[[nodiscard]] bool IsValidBridgeBatchLeafKind(BridgeBatchLeafKind kind);
[[nodiscard]] uint256 ComputeBridgeVerifierSetLeafHash(const BridgeKeySpec& attestor);
[[nodiscard]] uint256 ComputeBridgeVerifierSetRoot(Span<const BridgeKeySpec> attestors);
[[nodiscard]] std::optional<BridgeVerifierSetCommitment> BuildBridgeVerifierSetCommitment(Span<const BridgeKeySpec> attestors,
                                                                                          size_t required_signers);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeVerifierSetProof(const BridgeVerifierSetProof& proof);
[[nodiscard]] std::optional<BridgeVerifierSetProof> DeserializeBridgeVerifierSetProof(Span<const uint8_t> bytes);
[[nodiscard]] std::optional<BridgeVerifierSetProof> BuildBridgeVerifierSetProof(Span<const BridgeKeySpec> attestors,
                                                                                const BridgeKeySpec& attestor);
[[nodiscard]] bool VerifyBridgeVerifierSetProof(const BridgeVerifierSetCommitment& verifier_set,
                                                const BridgeKeySpec& attestor,
                                                const BridgeVerifierSetProof& proof);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProofSystemProfile(const BridgeProofSystemProfile& profile);
[[nodiscard]] std::optional<BridgeProofSystemProfile> DeserializeBridgeProofSystemProfile(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProofSystemId(const BridgeProofSystemProfile& profile);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProofClaim(const BridgeProofClaim& claim);
[[nodiscard]] std::optional<BridgeProofClaim> DeserializeBridgeProofClaim(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProofClaimHash(const BridgeProofClaim& claim);
[[nodiscard]] std::optional<BridgeProofClaim> BuildBridgeProofClaimFromStatement(const BridgeBatchStatement& statement,
                                                                                 BridgeProofClaimKind kind);
[[nodiscard]] bool DoesBridgeProofClaimMatchStatement(const BridgeProofClaim& claim,
                                                      const BridgeBatchStatement& statement);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProofAdapter(const BridgeProofAdapter& adapter);
[[nodiscard]] std::optional<BridgeProofAdapter> DeserializeBridgeProofAdapter(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProofAdapterId(const BridgeProofAdapter& adapter);
[[nodiscard]] std::optional<BridgeProofClaim> BuildBridgeProofClaimFromAdapter(const BridgeBatchStatement& statement,
                                                                               const BridgeProofAdapter& adapter);
[[nodiscard]] uint256 ComputeBridgeProofArtifactCommitment(Span<const uint8_t> bytes);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProofArtifact(const BridgeProofArtifact& artifact);
[[nodiscard]] std::optional<BridgeProofArtifact> DeserializeBridgeProofArtifact(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProofArtifactId(const BridgeProofArtifact& artifact);
[[nodiscard]] uint64_t GetBridgeProofArtifactStorageBytes(const BridgeProofArtifact& artifact);
[[nodiscard]] std::optional<BridgeDataArtifact> BuildBridgeDataArtifact(const BridgeBatchStatement& statement,
                                                                        BridgeDataArtifactKind kind,
                                                                        const uint256& payload_commitment,
                                                                        const uint256& artifact_commitment,
                                                                        uint32_t payload_size_bytes,
                                                                        uint32_t auxiliary_data_size_bytes);
[[nodiscard]] bool DoesBridgeDataArtifactMatchStatement(const BridgeDataArtifact& artifact,
                                                        const BridgeBatchStatement& statement);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeDataArtifact(const BridgeDataArtifact& artifact);
[[nodiscard]] std::optional<BridgeDataArtifact> DeserializeBridgeDataArtifact(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeDataArtifactId(const BridgeDataArtifact& artifact);
[[nodiscard]] uint64_t GetBridgeDataArtifactStorageBytes(const BridgeDataArtifact& artifact);
[[nodiscard]] std::optional<BridgeAggregateArtifactBundle> BuildBridgeAggregateArtifactBundle(
    const BridgeBatchStatement& statement,
    Span<const BridgeProofArtifact> proof_artifacts,
    Span<const BridgeDataArtifact> data_artifacts);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeAggregateArtifactBundle(const BridgeAggregateArtifactBundle& bundle);
[[nodiscard]] std::optional<BridgeAggregateArtifactBundle> DeserializeBridgeAggregateArtifactBundle(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeAggregateArtifactBundleId(const BridgeAggregateArtifactBundle& bundle);
[[nodiscard]] uint64_t GetBridgeAggregateArtifactBundleStorageBytes(const BridgeAggregateArtifactBundle& bundle);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeAggregateSettlement(const BridgeAggregateSettlement& settlement);
[[nodiscard]] std::optional<BridgeAggregateSettlement> DeserializeBridgeAggregateSettlement(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeAggregateSettlementId(const BridgeAggregateSettlement& settlement);
[[nodiscard]] std::optional<BridgeCapacityFootprint> BuildBridgeAggregateSettlementFootprint(const BridgeAggregateSettlement& settlement);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeShieldedStateProfile(const BridgeShieldedStateProfile& profile);
[[nodiscard]] std::optional<BridgeShieldedStateProfile> DeserializeBridgeShieldedStateProfile(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeShieldedStateProfileId(const BridgeShieldedStateProfile& profile);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeShieldedStateRetentionPolicy(const BridgeShieldedStateRetentionPolicy& policy);
[[nodiscard]] std::optional<BridgeShieldedStateRetentionPolicy> DeserializeBridgeShieldedStateRetentionPolicy(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeShieldedStateRetentionPolicyId(const BridgeShieldedStateRetentionPolicy& policy);
[[nodiscard]] std::optional<BridgeCapacityEstimate> EstimateBridgeCapacity(const BridgeCapacityFootprint& footprint,
                                                                           uint64_t block_serialized_limit,
                                                                           uint64_t block_weight_limit,
                                                                           std::optional<uint64_t> block_data_availability_limit = std::nullopt);
[[nodiscard]] std::optional<BridgeProofCompressionTarget> BuildBridgeProofCompressionTarget(
    const BridgeAggregateSettlement& settlement,
    const std::optional<BridgeAggregateArtifactBundle>& artifact_bundle,
    uint64_t block_serialized_limit,
    uint64_t block_weight_limit,
    std::optional<uint64_t> block_data_availability_limit,
    uint64_t target_users_per_block);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProofCompressionTarget(const BridgeProofCompressionTarget& target);
[[nodiscard]] std::optional<BridgeProofCompressionTarget> DeserializeBridgeProofCompressionTarget(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProofCompressionTargetId(const BridgeProofCompressionTarget& target);
[[nodiscard]] std::optional<BridgeProofCompressionEstimate> EstimateBridgeProofCompression(const BridgeProofCompressionTarget& target);
[[nodiscard]] std::optional<BridgeShieldedStateEstimate> EstimateBridgeShieldedStateGrowth(
    const BridgeAggregateSettlement& settlement,
    const BridgeShieldedStateProfile& profile,
    const BridgeCapacityEstimate& capacity,
    uint64_t block_interval_millis);
[[nodiscard]] std::optional<BridgeShieldedStateRetentionEstimate> EstimateBridgeShieldedStateRetention(
    const BridgeShieldedStateEstimate& state,
    const BridgeShieldedStateRetentionPolicy& policy);
[[nodiscard]] std::optional<BridgeProverCapacityEstimate> EstimateBridgeProverCapacity(const BridgeCapacityEstimate& l1_capacity,
                                                                                       const BridgeProverFootprint& footprint);
[[nodiscard]] std::optional<BridgeProverSample> BuildBridgeProverSample(const BridgeProofArtifact& artifact,
                                                                        uint64_t native_millis,
                                                                        uint64_t cpu_millis,
                                                                        uint64_t gpu_millis,
                                                                        uint64_t network_millis,
                                                                        uint64_t peak_memory_bytes);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProverSample(const BridgeProverSample& sample);
[[nodiscard]] std::optional<BridgeProverSample> DeserializeBridgeProverSample(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProverSampleId(const BridgeProverSample& sample);
[[nodiscard]] std::optional<BridgeProverProfile> BuildBridgeProverProfile(Span<const BridgeProverSample> samples);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProverProfile(const BridgeProverProfile& profile);
[[nodiscard]] std::optional<BridgeProverProfile> DeserializeBridgeProverProfile(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProverProfileId(const BridgeProverProfile& profile);
[[nodiscard]] std::optional<BridgeProverBenchmark> BuildBridgeProverBenchmark(Span<const BridgeProverProfile> profiles);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProverBenchmark(const BridgeProverBenchmark& benchmark);
[[nodiscard]] std::optional<BridgeProverBenchmark> DeserializeBridgeProverBenchmark(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProverBenchmarkId(const BridgeProverBenchmark& benchmark);
[[nodiscard]] uint64_t SelectBridgeProverMetric(const BridgeProverMetricSummary& summary,
                                                BridgeProverBenchmarkStatistic statistic);
[[nodiscard]] std::optional<BridgeProofArtifact> BuildBridgeProofArtifact(const BridgeBatchStatement& statement,
                                                                          const BridgeProofAdapter& adapter,
                                                                          const uint256& verifier_key_hash,
                                                                          const uint256& proof_commitment,
                                                                          const uint256& artifact_commitment,
                                                                          uint32_t proof_size_bytes,
                                                                          uint32_t public_values_size_bytes,
                                                                          uint32_t auxiliary_data_size_bytes);
[[nodiscard]] bool DoesBridgeProofArtifactMatchStatement(const BridgeProofArtifact& artifact,
                                                         const BridgeBatchStatement& statement);
[[nodiscard]] std::optional<BridgeProofDescriptor> BuildBridgeProofDescriptorFromProfile(const BridgeProofSystemProfile& profile,
                                                                                         const uint256& verifier_key_hash);
[[nodiscard]] std::optional<BridgeProofDescriptor> BuildBridgeProofDescriptorFromAdapter(const BridgeProofAdapter& adapter,
                                                                                         const uint256& verifier_key_hash);
[[nodiscard]] std::optional<BridgeProofDescriptor> BuildBridgeProofDescriptorFromArtifact(const BridgeProofArtifact& artifact);
[[nodiscard]] std::optional<BridgeProofAdapter> BuildCanonicalBridgeProofAdapter(BridgeProofClaimKind claim_kind,
                                                                                 size_t variant_index = 0);
[[nodiscard]] bool IsCanonicalBridgeProofSystemId(const uint256& proof_system_id);
[[nodiscard]] uint256 ComputeBridgeProofDescriptorLeafHash(const BridgeProofDescriptor& descriptor);
[[nodiscard]] uint256 ComputeBridgeProofPolicyRoot(Span<const BridgeProofDescriptor> descriptors);
[[nodiscard]] std::optional<BridgeProofPolicyCommitment> BuildBridgeProofPolicyCommitment(Span<const BridgeProofDescriptor> descriptors,
                                                                                          size_t required_receipts);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProofPolicyProof(const BridgeProofPolicyProof& proof);
[[nodiscard]] std::optional<BridgeProofPolicyProof> DeserializeBridgeProofPolicyProof(Span<const uint8_t> bytes);
[[nodiscard]] std::optional<BridgeProofPolicyProof> BuildBridgeProofPolicyProof(Span<const BridgeProofDescriptor> descriptors,
                                                                                const BridgeProofDescriptor& descriptor);
[[nodiscard]] bool VerifyBridgeProofPolicyProof(const BridgeProofPolicyCommitment& proof_policy,
                                                const BridgeProofDescriptor& descriptor,
                                                const BridgeProofPolicyProof& proof);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeVerificationBundle(const BridgeVerificationBundle& bundle);
[[nodiscard]] std::optional<BridgeVerificationBundle> DeserializeBridgeVerificationBundle(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeVerificationBundleHash(const BridgeVerificationBundle& bundle);
[[nodiscard]] std::optional<BridgeBatchAggregateCommitment> BuildDefaultBridgeBatchAggregateCommitment(
    const uint256& batch_root,
    const uint256& data_root,
    const BridgeProofPolicyCommitment& proof_policy);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeBatchAggregateCommitment(const BridgeBatchAggregateCommitment& commitment);
[[nodiscard]] std::optional<BridgeBatchAggregateCommitment> DeserializeBridgeBatchAggregateCommitment(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeBatchAggregateCommitmentHash(const BridgeBatchAggregateCommitment& commitment);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeBatchStatement(const BridgeBatchStatement& statement);
[[nodiscard]] std::optional<BridgeBatchStatement> DeserializeBridgeBatchStatement(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeBatchStatementHash(const BridgeBatchStatement& statement);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeBatchReceiptMessage(const BridgeBatchReceipt& receipt);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeBatchReceipt(const BridgeBatchReceipt& receipt);
[[nodiscard]] std::optional<BridgeBatchReceipt> DeserializeBridgeBatchReceipt(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeBatchReceiptHash(const BridgeBatchReceipt& receipt);
[[nodiscard]] bool VerifyBridgeBatchReceipt(const BridgeBatchReceipt& receipt);
[[nodiscard]] uint256 ComputeBridgeBatchReceiptLeafHash(const BridgeBatchReceipt& receipt);
[[nodiscard]] size_t CountDistinctBridgeBatchReceiptAttestors(Span<const BridgeBatchReceipt> receipts);
[[nodiscard]] uint256 ComputeBridgeBatchReceiptRoot(Span<const BridgeBatchReceipt> receipts);
[[nodiscard]] std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromStatement(const BridgeBatchStatement& statement,
                                                                                         Span<const BridgeBatchReceipt> receipts);
[[nodiscard]] std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromProfile(const BridgeBatchStatement& statement,
                                                                                   const BridgeProofSystemProfile& profile,
                                                                                   const uint256& verifier_key_hash,
                                                                                   const uint256& public_values_hash,
                                                                                   const uint256& proof_commitment);
[[nodiscard]] std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromProfile(const BridgeBatchStatement& statement,
                                                                                   const BridgeProofSystemProfile& profile,
                                                                                   const uint256& verifier_key_hash,
                                                                                   const BridgeProofClaim& claim,
                                                                                   const uint256& proof_commitment);
[[nodiscard]] std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromAdapter(const BridgeBatchStatement& statement,
                                                                                   const BridgeProofAdapter& adapter,
                                                                                   const uint256& verifier_key_hash,
                                                                                   const uint256& proof_commitment);
[[nodiscard]] std::optional<BridgeProofReceipt> BuildBridgeProofReceiptFromArtifact(const BridgeProofArtifact& artifact);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeProofReceipt(const BridgeProofReceipt& receipt);
[[nodiscard]] std::optional<BridgeProofReceipt> DeserializeBridgeProofReceipt(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeProofReceiptHash(const BridgeProofReceipt& receipt);
[[nodiscard]] uint256 ComputeBridgeProofReceiptLeafHash(const BridgeProofReceipt& receipt);
[[nodiscard]] size_t CountDistinctBridgeProofReceipts(Span<const BridgeProofReceipt> receipts);
[[nodiscard]] uint256 ComputeBridgeProofReceiptRoot(Span<const BridgeProofReceipt> receipts);
[[nodiscard]] std::optional<BridgeVerificationBundle> BuildBridgeVerificationBundle(
    Span<const BridgeBatchReceipt> receipts,
    Span<const BridgeProofReceipt> proof_receipts);
[[nodiscard]] std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromClaim(const BridgeBatchStatement& statement,
                                                                                     const BridgeProofClaim& claim);
[[nodiscard]] std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromProofReceipts(const BridgeBatchStatement& statement,
                                                                                             Span<const BridgeProofReceipt> receipts);
[[nodiscard]] std::optional<BridgeExternalAnchor> BuildBridgeExternalAnchorFromHybridWitness(const BridgeBatchStatement& statement,
                                                                                              Span<const BridgeBatchReceipt> receipts,
                                                                                              Span<const BridgeProofReceipt> proof_receipts);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeBatchAuthorizationMessage(const BridgeBatchAuthorization& authorization);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeBatchAuthorization(const BridgeBatchAuthorization& authorization);
[[nodiscard]] std::optional<BridgeBatchAuthorization> DeserializeBridgeBatchAuthorization(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeBatchAuthorizationHash(const BridgeBatchAuthorization& authorization);
[[nodiscard]] bool VerifyBridgeBatchAuthorization(const BridgeBatchAuthorization& authorization);
[[nodiscard]] bool UseBridgeBatchLeafTaggingAtHeight(int32_t height);
[[nodiscard]] uint256 ComputeBridgeBatchLeafWalletTag(const BridgeBatchAuthorization& authorization,
                                                      int32_t height);
[[nodiscard]] uint256 ComputeBridgeBatchLeafDestinationTag(const BridgeBatchAuthorization& authorization,
                                                           int32_t height);
[[nodiscard]] std::optional<BridgeBatchLeaf> BuildBridgeBatchLeafFromAuthorization(const BridgeBatchAuthorization& authorization,
                                                                                   int32_t height);
[[nodiscard]] std::optional<BridgeBatchLeaf> BuildBridgeBatchLeafFromAuthorization(const BridgeBatchAuthorization& authorization);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeBatchCommitment(const BridgeBatchCommitment& commitment);
[[nodiscard]] std::optional<BridgeBatchCommitment> DeserializeBridgeBatchCommitment(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeBatchLeafHash(const BridgeBatchLeaf& leaf);
[[nodiscard]] uint256 ComputeBridgeBatchRoot(Span<const BridgeBatchLeaf> leaves);
[[nodiscard]] uint256 ComputeBridgeBatchCommitmentHash(const BridgeBatchCommitment& commitment);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeAttestationMessage(const BridgeAttestationMessage& message);
[[nodiscard]] std::optional<BridgeAttestationMessage> DeserializeBridgeAttestationMessage(Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeBridgeAttestationHash(const BridgeAttestationMessage& message);
[[nodiscard]] std::optional<BridgeScriptTree> BuildShieldBridgeScriptTree(const uint256& ctv_hash,
                                                                          const BridgeKeySpec& normal_key,
                                                                          uint32_t refund_lock_height,
                                                                          const BridgeKeySpec& refund_key);
[[nodiscard]] std::optional<BridgeScriptTree> BuildUnshieldBridgeScriptTree(const uint256& ctv_hash,
                                                                            const BridgeKeySpec& attestation_key,
                                                                            uint32_t refund_lock_height,
                                                                            const BridgeKeySpec& refund_key);

} // namespace shielded

#endif // BTX_SHIELDED_BRIDGE_H
