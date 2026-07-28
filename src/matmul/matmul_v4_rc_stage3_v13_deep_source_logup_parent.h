// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_DEEP_SOURCE_LOGUP_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_DEEP_SOURCE_LOGUP_PARENT_H

#include <matmul/matmul_v4_rc_stage3_v13_quotient_tape_parent.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_deep_source_logup_parent {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace composer = stage3_air_parent_composer;
namespace gf = gkr_field;
namespace qp = stage3_v13_quotient_tape_parent;
namespace rv = stage3_multirow_v11_recursive_verifier;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kConsumerSlotsV1 = 10;
inline constexpr uint32_t kFieldLimbsV1 = 6;
inline constexpr uint32_t kTapeSlotsV1 =
    tape::kRecordsPerRowV1;
inline constexpr uint32_t kLookupLanesV1 = 2;
inline constexpr uint32_t kAdditionalColumnsV1 = 57;

enum class ConsumerKindV1 : uint8_t {
    DeepCurrent = 1,
    EvalZ1 = 2,
    EvalZ2 = 3,
    Z1 = 4,
    Z2 = 5,
    DeepWeight1 = 6,
    DeepWeight2 = 7,
    VmCurrent = 8,
    VmNext = 9,
    AirLambda = 10,
};
inline constexpr uint32_t kConsumerKindsV1 = 10;

struct OccurrenceV1 {
    ConsumerKindV1 kind{ConsumerKindV1::DeepCurrent};
    uint32_t query{0};
    uint32_t item{0};
    uint32_t row{0};
    uint32_t slot{0};
    uint32_t consumer_column{UINT32_MAX};
    abi::SourceKeyV1 key{};
    uint32_t source_address{UINT32_MAX};

    bool operator==(const OccurrenceV1&) const = default;
};

struct TapeSourceV1 {
    uint32_t address{UINT32_MAX};
    uint32_t multiplicity{0};
    uint32_t row{UINT32_MAX};
    uint32_t slot{UINT32_MAX};

    bool operator==(const TapeSourceV1&) const = default;
};

struct PlanV1 {
    uint16_t version{kVersionV1};
    tape::PublicShapeV1 shape{};
    rv::QueryRangeV1 range{};
    uint32_t parent_rows{0};
    uint32_t tape_column_base{0};
    uint32_t deep_column_base{0};
    std::vector<OccurrenceV1> occurrences;
    std::vector<TapeSourceV1> sources;
    uint64_t limb_occurrences{0};
    uint64_t source_multiplicity_sum{0};
    alg_hash::Digest plan_root{};
    bool exact_structural_rows{false};
    bool exact_v13_addresses{false};
    bool exact_multiplicities{false};
    bool proof_values_excluded{false};
    bool valid{false};
    std::string note;
};

struct ChallengesV1 {
    std::array<gf::Fp3, kLookupLanesV1> gamma{};
    std::array<gf::Fp3, kLookupLanesV1> alpha{};
};

struct LayoutV1 {
    uint32_t original_columns{0};
    uint32_t source_carry{0};
    uint32_t source_emit_value{0};
    uint32_t source_emit_active{0};
    uint32_t source_emit_address{0};
    uint32_t source_emit_multiplicity{0};
    uint32_t source_carry_weight_base{0};
    uint32_t source_emit_weight_base{0};
    uint32_t consumer_active_base{0};
    uint32_t consumer_address_base{0};
    uint32_t dependent_base{0};
    uint32_t source_inverse_base{0};
    uint32_t consumer_inverse_base{0};
    uint32_t running_base{0};
    uint32_t end{0};

    uint32_t SourceCarryWeight(uint32_t slot) const
    {
        return source_carry_weight_base + slot;
    }
    uint32_t SourceEmitWeight(uint32_t slot) const
    {
        return source_emit_weight_base + slot;
    }
    uint32_t ConsumerActive(uint32_t slot) const
    {
        return consumer_active_base + slot;
    }
    uint32_t ConsumerAddress(uint32_t slot) const
    {
        return consumer_address_base + slot;
    }
    uint32_t SourceInverse(uint32_t lane) const
    {
        return source_inverse_base + lane;
    }
    uint32_t ConsumerInverse(
        uint32_t lane, uint32_t slot) const
    {
        return consumer_inverse_base +
            lane * kConsumerSlotsV1 + slot;
    }
    uint32_t Running(uint32_t lane) const
    {
        return running_base + lane;
    }
};

/**
 * One physical parent over the already-attached V13 proof tape and canonical
 * DeepVM phase.  The source side streams the tape's ordinary canonical u32
 * Value cells through two ordinary Fp3 carry/emit columns.  Four immutable
 * per-row weights reconstruct each six-word Fp3 without allocating 6x32
 * consumer bit columns across the 2^22 tape domain.  The consumer side reads
 * the ten actual ordinary DeepVM value columns directly.
 *
 * Two post-R0 Fp3 LogUp lanes prove equality of
 *
 *   (canonical V13 base address, reconstructed Fp3) * exact multiplicity
 *      == (expected V13 base address, physical DeepVM Fp3)
 *
 * for every non-quotient, non-first-fold DEEP/VM occurrence.  Quotient and
 * first-fold ownership remain with their dedicated physical parents.
 */
struct ProductV1 {
    PlanV1 plan{};
    LayoutV1 layout{};
    ChallengesV1 challenges{};
    /** Metadata-only copy used to relocate the final LogUp relation into a
     * wider parent. Its heavy CS/witness vectors are cleared by builders. */
    qp::ProductV1 physical{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    uint32_t base_constraint_count{0};
    uint64_t violations{UINT64_MAX};
    bool every_occurrence_materialized{false};
    bool fp3_limb_reconstruction_constrained{false};
    bool canonical_u32_and_goldilocks_constrained{false};
    bool exact_source_multiplicity_constrained{false};
    bool physical_tape_stream_consumed{false};
    bool challenges_after_complete_r0{false};
    bool dual_fp3_terminal_cancelled{false};
    bool first_fold_owned_by_merkle_parent{true};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const stage3_multirow_v11_deep_vm::ProductV1& deep_product,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why = nullptr);

/**
 * Pre-challenge portion of ProductV1. It contains the complete physical
 * tape/quotient/DeepVM relation and all deterministic LogUp source/consumer
 * columns, but no inverse/running columns and no challenge-dependent
 * constraints. This is the form that can safely enter a wider parent before
 * that parent's single R0 commitment is sampled.
 */
struct BaseProductV1 {
    PlanV1 plan{};
    LayoutV1 layout{};
    qp::ProductV1 physical{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint64_t violations{UINT64_MAX};
    bool challenge_columns_absent{false};
    bool row_group_root_pending{false};
    bool valid{false};
    std::string note;
};

/**
 * Strip a validated standalone product back to its exact deterministic
 * pre-challenge relation. The discarded local challenge columns are never
 * reused in a parent.
 */
[[nodiscard]] bool ExtractBaseProductV1(
    const ProductV1& product,
    BaseProductV1& out,
    std::string* why = nullptr);

struct ParentFinalizationV1 {
    ChallengesV1 challenges{};
    LayoutV1 parent_layout{};
    std::vector<uint32_t> r0_base_column_indices;
    uint256 r0_row_root{};
    uint32_t dependent_columns{0};
    uint32_t constraints_appended{0};
    bool exact_parent_r0_consumed{false};
    bool all_prior_parent_columns_prechallenge{false};
    bool dual_fp3_terminal_cancelled{false};
    bool valid{false};
    std::string note;
};

/**
 * Append only the challenge-dependent LogUp columns/constraints after a base
 * product and any sibling relations already inhabit the same parent.
 *
 * The supplied session must commit every existing parent column, in order.
 * This prevents a prover from choosing a sibling witness after learning the
 * DEEP/quotient LogUp challenges. No child-local R0 root is accepted.
 */
[[nodiscard]] bool AppendFinalRelationToParentV1(
    const BaseProductV1& base,
    const composer::ChildAttachmentV1& base_attachment,
    const uint256& public_seed,
    const aq::AirQuotientTwoEpochBaseRowSession& parent_r0_session,
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    ParentFinalizationV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

enum class CanaryMutationV1 : uint8_t {
    Honest = 0,
    OmitOccurrence = 1,
    DuplicateOccurrence = 2,
    ReaddressOccurrence = 3,
    Fp3LimbSubstitution = 4,
    GoldilocksAliasXp = 5,
};

/**
 * Eight-row proof canary built through the same streaming reconstruction,
 * physical-consumer and dual-Fp3 LogUp appenders as BuildProductV1.  Its
 * bounded source pair copies the production tape AIR's canonical-u32 and
 * Goldilocks-pair equations. Mutation variants retain an otherwise coherent
 * witness and are intended for forced-inexact proof rejection tests.
 */
[[nodiscard]] ProductV1 BuildBoundedCanaryV1(
    CanaryMutationV1 mutation,
    const uint256& public_seed,
    std::string* why = nullptr);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kRecursiveConsumptionV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;
static_assert(!kRecursiveConsumptionV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_deep_source_logup_parent

#endif
