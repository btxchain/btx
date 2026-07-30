// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_TEMPORAL_INDUCTION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_TEMPORAL_INDUCTION_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>

#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_temporal {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kTemporalInductionVersionV1 = 1;
inline constexpr uint32_t kTemporalRootWordsV1 = 8;
inline constexpr uint32_t kTemporalInductionMaxRoundsV1 = 1U << 24;

/*
 * These are deliberately false at the foundation seam.  This AIR closes the
 * ordered temporal chain itself; it does not claim that a relation endpoint
 * has already been directly aliased into the chain, nor that a normalized
 * parent has recursively verified this AIR's proof.
 */
inline constexpr bool kTemporalDirectEndpointAliasesInstalledV1 = false;
inline constexpr bool kTemporalRecursivelyConsumedV1 = false;

/**
 * Canonical 256-bit root representation for the temporal AIR.
 *
 * Roots are eight u32 words, not four u64 field elements.  Consequently no
 * two host roots differing by the Goldilocks modulus can become the same AIR
 * input through `FromU64(x) = x mod p`.
 */
struct TemporalRootU32V1 {
    std::array<uint32_t, kTemporalRootWordsV1> words{};

    bool operator==(const TemporalRootU32V1&) const = default;
};

/** Exact little-endian uint256 <-> eight-u32 transcript cell mapping. */
[[nodiscard]] TemporalRootU32V1 EncodeTemporalRootU32V1(
    const uint256& root);
[[nodiscard]] uint256 DecodeTemporalRootU32V1(
    const TemporalRootU32V1& root);

struct TemporalTransitionV1 {
    uint32_t round{0};
    TemporalRootU32V1 input_root{};
    TemporalRootU32V1 output_root{};

    bool operator==(const TemporalTransitionV1&) const = default;
};

/**
 * Verifier-owned ordered transition manifest.
 *
 * `n_rows` is canonical: the smallest power of two strictly larger than
 * `expected_rounds`.  The extra row is load-bearing because it makes the
 * final-active -> padding transition an ordinary non-wrapping AIR transition.
 */
struct TemporalInductionManifestV1 {
    uint16_t version{kTemporalInductionVersionV1};
    uint32_t expected_rounds{0};
    uint32_t n_rows{0};
    TemporalRootU32V1 base_root{};
    TemporalRootU32V1 final_root{};
    std::vector<TemporalTransitionV1> transitions;
    uint256 commitment{};

    bool operator==(const TemporalInductionManifestV1&) const = default;
};

/**
 * Reject a non-canonical raw Fp3 representation before it enters an AIR
 * witness.  Algebra cannot distinguish x from x+p after field reduction, so
 * this check belongs at the serialization/loader boundary.  Every accepted
 * lane is an embedded canonical u32 with zero extension limbs.
 */
[[nodiscard]] bool DecodeCanonicalTemporalRootU32V1(
    const std::array<gf::Fp3, kTemporalRootWordsV1>& lanes,
    TemporalRootU32V1& out,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CanonicalTemporalTraceRowsV1(
    uint32_t expected_rounds);

[[nodiscard]] uint256 ComputeTemporalInductionCommitmentV1(
    const TemporalInductionManifestV1& manifest);

[[nodiscard]] bool ValidateTemporalInductionManifestV1(
    const TemporalInductionManifestV1& manifest,
    std::string* why = nullptr);

[[nodiscard]] bool BuildTemporalInductionManifestV1(
    uint32_t expected_rounds,
    const TemporalRootU32V1& expected_base_root,
    const TemporalRootU32V1& expected_final_root,
    const std::vector<TemporalTransitionV1>& transitions,
    TemporalInductionManifestV1& out,
    std::string* why = nullptr);

/**
 * One semantic row uses:
 *   ACTIVE, PADDING, BASE, FINAL, ROUND, INPUT_ROOT[8], OUTPUT_ROOT[8].
 * An equally sized verifier-owned preprocessed row follows it.
 */
struct TemporalInductionLayoutV1 {
    static constexpr uint32_t kActiveField = 0;
    static constexpr uint32_t kPaddingField = 1;
    static constexpr uint32_t kBaseField = 2;
    static constexpr uint32_t kFinalField = 3;
    static constexpr uint32_t kRoundField = 4;
    static constexpr uint32_t kInputField = 5;
    static constexpr uint32_t kOutputField =
        kInputField + kTemporalRootWordsV1;
    static constexpr uint32_t kSemanticFields =
        kOutputField + kTemporalRootWordsV1;
    static constexpr uint32_t kColumns = 2 * kSemanticFields;

    uint32_t base{0};

    explicit constexpr TemporalInductionLayoutV1(uint32_t start = 0)
        : base(start)
    {
    }

    [[nodiscard]] constexpr uint32_t Witness(uint32_t field) const
    {
        return base + field;
    }
    [[nodiscard]] constexpr uint32_t Expected(uint32_t field) const
    {
        return base + kSemanticFields + field;
    }
    [[nodiscard]] constexpr uint32_t Active() const
    {
        return Witness(kActiveField);
    }
    [[nodiscard]] constexpr uint32_t Padding() const
    {
        return Witness(kPaddingField);
    }
    [[nodiscard]] constexpr uint32_t BaseSelector() const
    {
        return Witness(kBaseField);
    }
    [[nodiscard]] constexpr uint32_t FinalSelector() const
    {
        return Witness(kFinalField);
    }
    [[nodiscard]] constexpr uint32_t Round() const
    {
        return Witness(kRoundField);
    }
    [[nodiscard]] constexpr uint32_t Input(uint32_t word) const
    {
        return Witness(kInputField + word);
    }
    [[nodiscard]] constexpr uint32_t Output(uint32_t word) const
    {
        return Witness(kOutputField + word);
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return base + kColumns;
    }
};

struct TemporalInductionAirV1 {
    TemporalInductionLayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint256 manifest_commitment{};
    uint32_t violations{1};
    bool verifier_owned_preprocessed_rows{false};
    bool base_anchor_constrained{false};
    bool strict_round_increment_constrained{false};
    bool transition_continuity_constrained{false};
    bool final_anchor_constrained{false};
    bool active_padding_constrained{false};
    bool direct_endpoint_aliases_installed{
        kTemporalDirectEndpointAliasesInstalledV1};
    bool recursively_consumed{kTemporalRecursivelyConsumedV1};
    bool valid{false};
    std::string note;
};

struct TemporalInductionAttachmentV1 {
    TemporalInductionLayoutV1 layout{};
    uint32_t constraint_base{0};
    uint32_t constraints_added{0};
    uint32_t columns_added{0};
    uint32_t violations{1};
    bool verifier_owned_preprocessed_rows{false};
    bool base_anchor_constrained{false};
    bool strict_round_increment_constrained{false};
    bool transition_continuity_constrained{false};
    bool final_anchor_constrained{false};
    bool active_padding_constrained{false};
    bool direct_endpoint_aliases_installed{
        kTemporalDirectEndpointAliasesInstalledV1};
    bool recursively_consumed{kTemporalRecursivelyConsumedV1};
    bool valid{false};
    std::string note;
};

[[nodiscard]] uint32_t CountTemporalInductionViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t* first_row = nullptr,
    std::string* first_constraint = nullptr);

[[nodiscard]] TemporalInductionAirV1 BuildTemporalInductionAirV1(
    const TemporalInductionManifestV1& verifier_manifest);

/**
 * Append this construction to an existing normalized-parent trace.
 *
 * The parent must already have the exact canonical row count.  The function
 * only installs the temporal AIR and its public preprocessing; the two
 * readiness-facing booleans remain false until separate endpoint aliases and
 * recursive child-proof consumption are installed by their owning modules.
 */
[[nodiscard]] TemporalInductionAttachmentV1
AppendTemporalInductionToParentV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const TemporalInductionManifestV1& verifier_manifest);

} // namespace matmul::v4::rc::stage3_temporal

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_TEMPORAL_INDUCTION_H
