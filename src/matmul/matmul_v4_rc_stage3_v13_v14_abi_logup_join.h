// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_V14_ABI_LOGUP_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_V14_ABI_LOGUP_JOIN_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_v13_occurrence_manifest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_v14_abi_logup_join {

namespace aq = air_quotient;
namespace bridge = stage3_safe_v12_recursive_bridge;
namespace gf = gkr_field;
namespace manifest = stage3_v13_occurrence_manifest;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kAbiLogUpJoinVersionV1 = 1;
inline constexpr uint32_t kSourceByteSlotsPerRowV1 =
    tape::kRecordsPerRowV1 * 4;
inline constexpr uint32_t kConsumerByteSlotsPerRowV1 =
    safe_v12::kSafeRateV12 * 4;
inline constexpr uint32_t kLookupLanesV1 = 2;

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    bool operator==(const CellRefV1&) const = default;
};

/**
 * One distinct canonical proof-tape source byte.  A source appears once in
 * the lookup table with `multiplicity` equal to its exact number of V14
 * transcript consumers.
 */
struct SourceByteV1 {
    uint32_t abi_address{UINT32_MAX};
    uint8_t byte_in_word{0};
    uint32_t multiplicity{0};
    uint32_t lookup_slot{UINT32_MAX};
    CellRefV1 address;
    CellRefV1 value;
    std::array<CellRefV1, 8> byte_bits{};

    bool operator==(const SourceByteV1&) const = default;
};

/** One canonical-ABI byte occurrence in one actual V14 Message(lane) cell. */
struct ConsumerByteV1 {
    uint32_t abi_address{UINT32_MAX};
    uint8_t byte_in_abi_word{0};
    uint8_t byte_in_message_word{0};
    uint32_t lookup_slot{UINT32_MAX};
    CellRefV1 message;

    bool operator==(const ConsumerByteV1&) const = default;
};

/**
 * Verifier-rebuilt schedule.  `plan_root` binds every physical same-parent
 * cell reference, key and multiplicity before the lookup challenges.
 */
struct PlanV1 {
    uint16_t version{kAbiLogUpJoinVersionV1};
    tape::PublicShapeV1 shape{};
    alg_hash::Digest v14_program_root{};
    uint32_t parent_rows{0};
    uint32_t tape_column_offset{0};
    uint32_t v14_column_offset{0};
    std::vector<SourceByteV1> sources;
    std::vector<ConsumerByteV1> consumers;
    uint32_t unique_source_bytes{0};
    uint32_t consumer_occurrences{0};
    uint64_t source_multiplicity_sum{0};
    alg_hash::Digest plan_root{};
    bool exact_manifest_rebuild{false};
    bool exact_physical_cell_map{false};
    bool exact_multiplicity_accounting{false};
    bool valid{false};
    std::string note;
};

/**
 * Rebuild the exact canonical-ABI subrelation from public shape/program.
 *
 * The offsets name already-resident proof-tape and V14 column families in a
 * future normalized parent.  Values never enter this builder.
 */
[[nodiscard]] bool BuildCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const std::vector<bridge::TypedSafeEventProgramV13>& v14_program,
    const manifest::ManifestV1& occurrence_manifest,
    uint32_t parent_rows,
    uint32_t tape_column_offset,
    uint32_t v14_column_offset,
    PlanV1& out,
    std::string* why = nullptr);

/** Rebuild-and-compare validation; no prover-supplied schedule is trusted. */
[[nodiscard]] bool ValidateCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const std::vector<bridge::TypedSafeEventProgramV13>& v14_program,
    const manifest::ManifestV1& occurrence_manifest,
    const PlanV1& claimed,
    std::string* why = nullptr);

struct ChallengesV1 {
    std::array<gf::Fp3, kLookupLanesV1> gamma{};
    std::array<gf::Fp3, kLookupLanesV1> alpha{};

    bool operator==(const ChallengesV1& other) const
    {
        for (uint32_t lane = 0; lane < kLookupLanesV1; ++lane) {
            if (!gf::Eq(gamma[lane], other.gamma[lane]) ||
                !gf::Eq(alpha[lane], other.alpha[lane])) {
                return false;
            }
        }
        return true;
    }
};

/**
 * Challenges are Poseidon2/SAFE-derived from:
 *
 *   public seed || exact plan root || complete parent R0 row root.
 *
 * Thus no address, value, consumer or multiplicity may be selected after
 * gamma/alpha is known.
 */
[[nodiscard]] bool DeriveChallengesV1(
    const PlanV1& plan,
    const uint256& public_seed,
    const uint256& parent_r0_row_root,
    ChallengesV1& out,
    std::string* why = nullptr);

struct LayoutV1 {
    uint32_t original_columns{0};
    uint32_t consumer_bit_base{0};
    uint32_t consumer_decompose_mask_base{0};
    uint32_t source_active_base{0};
    uint32_t source_multiplicity_base{0};
    uint32_t consumer_active_base{0};
    uint32_t consumer_key_base{0};
    uint32_t dependent_base{0};
    uint32_t source_inverse_base{0};
    uint32_t consumer_inverse_base{0};
    uint32_t running_base{0};
    uint32_t end{0};

    [[nodiscard]] uint32_t ConsumerBit(
        uint32_t lane, uint32_t bit) const
    {
        return consumer_bit_base + 32 * lane + bit;
    }
    [[nodiscard]] uint32_t ConsumerDecomposeMask(
        uint32_t lane) const
    {
        return consumer_decompose_mask_base + lane;
    }
    [[nodiscard]] uint32_t SourceActive(
        uint32_t slot) const
    {
        return source_active_base + slot;
    }
    [[nodiscard]] uint32_t SourceMultiplicity(
        uint32_t slot) const
    {
        return source_multiplicity_base + slot;
    }
    [[nodiscard]] uint32_t ConsumerActive(
        uint32_t slot) const
    {
        return consumer_active_base + slot;
    }
    [[nodiscard]] uint32_t ConsumerKey(
        uint32_t slot) const
    {
        return consumer_key_base + slot;
    }
    [[nodiscard]] uint32_t SourceInverse(
        uint32_t lane, uint32_t slot) const
    {
        return source_inverse_base +
            lane * kSourceByteSlotsPerRowV1 + slot;
    }
    [[nodiscard]] uint32_t ConsumerInverse(
        uint32_t lane, uint32_t slot) const
    {
        return consumer_inverse_base +
            lane * kConsumerByteSlotsPerRowV1 + slot;
    }
    [[nodiscard]] uint32_t Running(uint32_t lane) const
    {
        return running_base + lane;
    }
};

struct ProductV1 {
    PlanV1 plan;
    LayoutV1 layout;
    ChallengesV1 challenges;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    uint64_t violations{0};
    bool actual_tape_cells_referenced{false};
    bool actual_v14_message_cells_referenced{false};
    bool consumer_u32_decomposition_constrained{false};
    bool exact_schedule_multiplicities_preprocessed{false};
    bool challenges_after_complete_r0{false};
    bool dual_fp3_rational_identity_constrained{false};
    bool terminal_cancellation_constrained{false};
    /**
     * These remain false until a normalized parent embeds both full source
     * constraint families and recursively consumes this joined proof.
     */
    bool source_and_consumer_verifiers_resident{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Append the join to an existing parent witness and prepare the retained R0.
 *
 * `parent_r0_base_column_indices` must already contain every referenced tape
 * Address/Value/Bit and V14 Message column.  The builder adds only ordinary
 * consumer decomposition bits, public schedule columns and lookup
 * auxiliaries; actual source/consumer values are never mirrored.
 */
[[nodiscard]] bool BuildProductV1(
    const PlanV1& plan,
    const uint256& public_seed,
    const aq::AirConstraintSystem<gf::Fp3>& resident_parent_cs,
    const std::vector<std::vector<gf::Fp3>>& resident_parent_columns,
    const std::vector<uint32_t>& parent_r0_base_column_indices,
    ProductV1& out,
    std::string* why = nullptr);

struct ProofV1 {
    uint16_t version{kAbiLogUpJoinVersionV1};
    alg_hash::Digest plan_root{};
    uint256 r0_row_root{};
    aq::AirQuotientSplitRapRowsProof proof;
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    const uint256& public_seed,
    ProofV1& out,
    std::string* why = nullptr);

/**
 * Rebuilds and compares the entire canonical plan from public shape/program,
 * derives challenges from the proof's authenticated R0 root, then invokes the
 * unmodified SAFE Split-RAP verifier.
 */
[[nodiscard]] bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const std::vector<bridge::TypedSafeEventProgramV13>& v14_program,
    const manifest::ManifestV1& occurrence_manifest,
    const PlanV1& canonical_plan,
    const uint256& public_seed,
    const aq::AirConstraintSystem<gf::Fp3>& resident_parent_cs,
    const std::vector<uint32_t>& parent_r0_base_column_indices,
    const ProofV1& proof,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kAbiLogUpJoinExecutableV1 = true;
inline constexpr bool kAbiLogUpJoinRecursiveConsumptionV1 = false;
inline constexpr bool kAbiLogUpJoinAuthorityReadyV1 = false;

static_assert(!kAbiLogUpJoinRecursiveConsumptionV1);
static_assert(!kAbiLogUpJoinAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_v14_abi_logup_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_V14_ABI_LOGUP_JOIN_H
