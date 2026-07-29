// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_MERKLE_FOLD_DESCRIPTOR_VM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_MERKLE_FOLD_DESCRIPTOR_VM_H

#include <matmul/matmul_v4_rc_stage3_v13_merkle_fold_parent.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_merkle_fold_descriptor_vm {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace gf = gkr_field;
namespace merkle = stage3_v13_merkle_fold_parent;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kTapeShardsV1 = 4;
inline constexpr uint32_t kSourceSlotsV1 = 64;
inline constexpr uint32_t kLookupLanesV1 = 2;
inline constexpr uint32_t kShardSourceSlotsV1 =
    alg_hash::kAlgHashRate;
inline constexpr uint32_t kHashLanesV1 = alg_hash::kAlgHashT;
inline constexpr uint32_t kHashOutputLanesV1 =
    alg_hash::kAlgHashDigestLen;
inline constexpr uint32_t kFoldInputLanesV1 = 7;
inline constexpr uint32_t kHashSelectorSlotV1 =
    2 * kHashLanesV1;
inline constexpr uint32_t kHashOutputSlotBaseV1 =
    kHashSelectorSlotV1 + 1;
inline constexpr uint32_t kMaxManifestReadsV1 = 1U << 28;

static_assert(kHashOutputSlotBaseV1 +
                  2 * kHashOutputLanesV1 <=
              kSourceSlotsV1);

enum class FamilyV1 : uint8_t {
    Hash = 1,
    Fold = 2,
};

enum class TerminalFamilyV1 : uint8_t {
    Tape = 1,
    HashInput = 2,
    PriorOutput = 3,
    HashOutputAlias = 4,
    FoldInput = 5,
};

struct SourceCellV1 {
    uint64_t global_ordinal{UINT64_MAX};
    uint32_t address{UINT32_MAX};
    abi::SourceKeyV1 key{};
    uint32_t row{UINT32_MAX};
    uint32_t slot{UINT32_MAX};

    bool operator==(const SourceCellV1&) const = default;
};

/**
 * Public receipt metadata for one ordinary-R0 tape shard.  A shard starts
 * from and ends at the full twelve-lane Poseidon state; comparing only the
 * four digest lanes is unsound because the capacity lanes affect the next
 * permutation.  Shard zero alone starts at the canonical all-zero state.
 */
struct SourceShardV1 {
    uint16_t version{kVersionV1};
    uint32_t shard_ordinal{UINT32_MAX};
    uint64_t global_ordinal_begin{UINT64_MAX};
    uint64_t global_ordinal_end{UINT64_MAX};
    uint32_t trace_rows{0};
    std::vector<SourceCellV1> cells;
    alg_hash::Digest source_domain_root{};
    alg_hash::State state_in{};
    alg_hash::State state_out{};
    bool last_shard{false};
    bool exact_contiguous_interval{false};
    bool state_boundary_bound{false};
    bool valid{false};
    std::string note;

    bool operator==(const SourceShardV1&) const = default;
};

struct SourceSlotV1 {
    bool active{false};
    uint32_t source_shard_ordinal{UINT32_MAX};
    uint64_t global_ordinal{UINT64_MAX};
    uint32_t address{UINT32_MAX};
    abi::SourceKeyV1 key{};

    bool operator==(const SourceSlotV1&) const = default;
};

struct HashLaneDescriptorV1 {
    gf::Fp3 w0{};
    gf::Fp3 w1{};
    gf::Fp3 w_prior{};
    gf::Fp3 w_effective_index{};
    gf::Fp3 constant{};
    bool select_left{false};
    bool select_right{false};
    bool prior_active{false};
    uint32_t prior_task_row{UINT32_MAX};
    uint32_t prior_output_lane{UINT32_MAX};

    bool operator==(const HashLaneDescriptorV1& other) const;
};

struct RowDescriptorV1 {
    bool active{false};
    uint32_t task_ordinal{UINT32_MAX};
    std::array<SourceSlotV1, kSourceSlotsV1> source{};
    std::array<HashLaneDescriptorV1, kHashLanesV1> hash_lane{};
    bool selector_active{false};
    bool selector_is_derived_next{false};
    uint8_t selector_bit{0};
    std::array<bool, kHashOutputLanesV1> hash_output_active{};

    bool operator==(const RowDescriptorV1&) const = default;
};

/**
 * The descriptor is a public, exact manifest.  It may read from any of the
 * four canonical tape shards.  Every active source slot carries its shard and
 * global ordinal, so a prover cannot relabel or transplant an equal-valued
 * source across shard boundaries.
 */
struct PlanV1 {
    uint16_t version{kVersionV1};
    FamilyV1 family{FamilyV1::Hash};
    uint64_t family_tag{0};
    std::array<SourceShardV1, kTapeShardsV1> source_shards{};
    /** Four canonical digest lanes of the proof tape's final sponge state. */
    alg_hash::Digest proof_tape_root{};
    uint256 source_inventory_root{};
    uint32_t parent_rows{0};
    uint32_t relation_rows{0};
    uint32_t selector_n_lde{0};
    uint32_t selector_stride{0};
    std::vector<RowDescriptorV1> rows;
    std::array<std::vector<uint32_t>, kTapeShardsV1>
        source_multiplicity;
    uint32_t manifest_reads{0};
    alg_hash::Digest schedule_root{};
    bool exact_relation_schedule{false};
    bool exact_source_multiplicity{false};
    bool exact_prior_memory_schedule{false};
    bool exact_manifest_count{false};
    bool zero_padding_canonical{false};
    bool valid{false};
    std::string note;

    bool operator==(const PlanV1&) const = default;
};

[[nodiscard]] bool BuildHashPlanV1(
    const std::array<SourceShardV1, kTapeShardsV1>&
        source_shards,
    const uint256& source_inventory_root,
    uint64_t family_tag,
    uint32_t parent_rows,
    uint32_t selector_n_lde,
    uint32_t selector_stride,
    const merkle::TypedHashPlanV1& hash_plan,
    PlanV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildFoldPlanV1(
    const std::array<SourceShardV1, kTapeShardsV1>&
        source_shards,
    const uint256& source_inventory_root,
    uint64_t family_tag,
    uint32_t parent_rows,
    const merkle::TypedFoldPlanV1& fold_plan,
    PlanV1& out,
    std::string* why = nullptr);

struct LayoutV1 {
    uint32_t source_value_base{UINT32_MAX};
    uint32_t source_active_base{UINT32_MAX};
    uint32_t source_global_ordinal_base{UINT32_MAX};
    uint32_t source_address_tag_base{UINT32_MAX};
    uint32_t coverage_root_base{UINT32_MAX};
    uint32_t row_active{UINT32_MAX};
    uint32_t task_ordinal{UINT32_MAX};
    uint32_t hash_coefficient_base{UINT32_MAX};
    uint32_t hash_prior_active_base{UINT32_MAX};
    uint32_t hash_prior_task_base{UINT32_MAX};
    uint32_t hash_prior_lane_base{UINT32_MAX};
    uint32_t hash_selector_active{UINT32_MAX};
    uint32_t hash_selector_derived{UINT32_MAX};
    uint32_t hash_selector_choice_base{UINT32_MAX};
    uint32_t hash_output_active_base{UINT32_MAX};
    uint32_t hash_source_selector_bit_base{UINT32_MAX};
    uint32_t hash_effective_selector{UINT32_MAX};
    uint32_t hash_effective_selector_bit_base{UINT32_MAX};
    uint32_t hash_selector_wrap{UINT32_MAX};
    uint32_t hash_selected_bit{UINT32_MAX};
    uint32_t hash_prior_value_base{UINT32_MAX};
    uint32_t hash_expected_input_base{UINT32_MAX};
    uint32_t deterministic_end{UINT32_MAX};
    uint32_t tape_consumer_inverse_base{UINT32_MAX};
    uint32_t hash_input_inverse_base{UINT32_MAX};
    uint32_t prior_consumer_inverse_base{UINT32_MAX};
    uint32_t hash_output_inverse_base{UINT32_MAX};
    uint32_t fold_input_inverse_base{UINT32_MAX};
    uint32_t running_base{UINT32_MAX};
    uint32_t terminal_base{UINT32_MAX};
    uint32_t acceptance{UINT32_MAX};
    uint32_t end{UINT32_MAX};

    [[nodiscard]] uint32_t SourceValue(uint32_t slot) const;
    [[nodiscard]] uint32_t SourceActive(uint32_t slot) const;
    [[nodiscard]] uint32_t SourceGlobalOrdinal(uint32_t slot) const;
    [[nodiscard]] uint32_t SourceAddressTag(uint32_t slot) const;
    [[nodiscard]] uint32_t CoverageRoot(uint32_t limb) const;
    [[nodiscard]] uint32_t HashCoefficient(
        uint32_t lane, uint32_t coefficient) const;
    [[nodiscard]] uint32_t HashPriorActive(uint32_t lane) const;
    [[nodiscard]] uint32_t HashPriorTask(uint32_t lane) const;
    [[nodiscard]] uint32_t HashPriorLane(uint32_t lane) const;
    [[nodiscard]] uint32_t HashSelectorChoice(uint32_t bit) const;
    [[nodiscard]] uint32_t HashOutputActive(uint32_t lane) const;
    [[nodiscard]] uint32_t HashSourceSelectorBit(uint32_t bit) const;
    [[nodiscard]] uint32_t HashEffectiveSelectorBit(uint32_t bit) const;
    [[nodiscard]] uint32_t HashPriorValue(uint32_t lane) const;
    [[nodiscard]] uint32_t HashExpectedInput(uint32_t lane) const;
    [[nodiscard]] uint32_t TapeConsumerInverse(
        uint32_t lane, uint32_t slot) const;
    [[nodiscard]] uint32_t HashInputInverse(
        uint32_t lane, uint32_t input_lane) const;
    [[nodiscard]] uint32_t PriorConsumerInverse(
        uint32_t lane, uint32_t output_lane) const;
    [[nodiscard]] uint32_t HashOutputInverse(
        uint32_t lane, uint32_t output_lane) const;
    [[nodiscard]] uint32_t FoldInputInverse(
        uint32_t lane, uint32_t input_lane) const;
    [[nodiscard]] uint32_t Running(
        TerminalFamilyV1 family, uint32_t shard,
        uint32_t lane) const;
    [[nodiscard]] uint32_t Terminal(
        TerminalFamilyV1 family, uint32_t shard,
        uint32_t lane) const;
};

struct DeterministicAttachmentV1 {
    PlanV1 plan{};
    LayoutV1 layout{};
    uint32_t columns_appended{0};
    uint32_t preprocessed_columns{0};
    uint32_t constraints_appended{0};
    alg_hash::Digest deterministic_program_root{};
    bool source_values_ordinary{false};
    bool fixed_schedule_preprocessed{false};
    bool prior_memory_values_ordinary{false};
    bool unused_slots_zero_constrained{false};
    bool v3_scalar_challenges{false};
    bool degree_caps_closed{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool AppendDeterministicConstraintSystemV1(
    const PlanV1& plan,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    DeterministicAttachmentV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool AppendDeterministicWitnessV1(
    const PlanV1& plan,
    const abi::DecodedV1& decoded,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns,
    DeterministicAttachmentV1& out,
    std::string* why = nullptr);

struct ChallengesV1 {
    std::array<gf::Fp3, kLookupLanesV1> gamma{};
    std::array<gf::Fp3, kLookupLanesV1> alpha{};

    bool operator==(const ChallengesV1&) const = default;
};

[[nodiscard]] uint256 ComputePublicTapeChallengeSeedV1(
    const alg_hash::Digest& proof_tape_root,
    const uint256& source_inventory_root);

struct TerminalReceiptV1 {
    alg_hash::Digest schedule_root{};
    std::array<alg_hash::Digest, kTapeShardsV1>
        tape_domain_root{};
    std::array<alg_hash::State, kTapeShardsV1> state_in{};
    std::array<alg_hash::State, kTapeShardsV1> state_out{};
    std::array<gf::Fp3, kLookupLanesV1> tape_consumer{};
    std::array<gf::Fp3, kLookupLanesV1> hash_input{};
    std::array<gf::Fp3, kLookupLanesV1> prior_output{};
    std::array<gf::Fp3, kLookupLanesV1> hash_output{};
    std::array<gf::Fp3, kLookupLanesV1> fold_input{};
    uint32_t manifest_reads{0};
    bool exact_four_shards{false};
    bool full_state_bound{false};
    bool exact_manifest_count{false};
    bool valid{false};
    std::string note;
};

struct FinalizationV1 {
    ChallengesV1 challenges{};
    TerminalReceiptV1 receipt{};
    uint32_t dependent_column_base{UINT32_MAX};
    uint32_t dependent_columns{0};
    uint32_t constraints_appended{0};
    std::array<uint32_t, kLookupLanesV1>
        tape_terminal_column{};
    std::array<uint32_t, kLookupLanesV1>
        hash_input_terminal_column{};
    std::array<uint32_t, kLookupLanesV1>
        prior_output_terminal_column{};
    std::array<uint32_t, kLookupLanesV1>
        hash_output_terminal_column{};
    std::array<uint32_t, kLookupLanesV1>
        fold_input_terminal_column{};
    alg_hash::Digest final_program_root{};
    bool public_tape_root_challenges{false};
    bool dual_fp3_terminals{false};
    bool terminal_cells_constrained{false};
    bool v3_scalar_challenges{false};
    bool degree_caps_closed{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool DeriveChallengesV1(
    const PlanV1& plan,
    ChallengesV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool AppendFinalConstraintSystemV1(
    const DeterministicAttachmentV1& deterministic,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    FinalizationV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool AppendFinalWitnessV1(
    const DeterministicAttachmentV1& deterministic,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns,
    FinalizationV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kRecursivelyConsumedV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kRecursivelyConsumedV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_merkle_fold_descriptor_vm

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_MERKLE_FOLD_DESCRIPTOR_VM_H
