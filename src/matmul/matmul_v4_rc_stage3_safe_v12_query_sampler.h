// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_QUERY_SAMPLER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_QUERY_SAMPLER_H

#include <matmul/matmul_v4_rc_air_quotient.h>

#include <cstdint>
#include <string>
#include <vector>

/**
 * Bounded without-replacement sampler for one V12 Q96 FRI lane.
 *
 * SAFE squeezes 128 typed Fp3 candidates.  The protocol masks the low
 * log2(n_lde) bits of each canonical c0 limb and takes the first 96 distinct
 * indices in transcript order.  Fewer than 96 distinct candidates is a
 * fail-closed transcript exhaustion.
 *
 * The AIR avoids an O(C^2) equality matrix.  At row i it carries
 *
 *     P_i(X) = product_{j already selected} (X - q_j).
 *
 * Candidate x_i is new iff P_i(x_i) != 0.  A constrained inverse/zero test,
 * a one-hot selected-count state and the polynomial coefficient transition
 * therefore enforce first-distinct order, uniqueness and exact exhaustion.
 * Full 64-bit decomposition plus Goldilocks canonicity prevents x and x+p
 * from selecting different masked indices.
 */
namespace matmul::v4::rc::stage3_safe_v12_query_sampler {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint32_t kQueriesV12 = 96;
inline constexpr uint32_t kCandidatesV12 = 128;
inline constexpr uint32_t kCandidateLanesV12 = 3;
inline constexpr uint32_t kTraceRowsV12 = 256;
inline constexpr uint32_t kLaneBitsV12 = 64;
inline constexpr uint32_t kHighBitsV12 = 32;
inline constexpr uint32_t kAndChunkV12 = 6;
inline constexpr uint32_t kAndStepsV12 =
    (kHighBitsV12 + kAndChunkV12 - 1) / kAndChunkV12;

struct LayoutV12 {
    uint32_t candidate_base{0};
    uint32_t bit_base{candidate_base + kCandidateLanesV12};
    uint32_t and_base{bit_base + kLaneBitsV12};
    uint32_t index{and_base + kAndStepsV12};
    uint32_t evaluation{index + 1};
    uint32_t inverse{evaluation + 1};
    uint32_t unique{inverse + 1};
    uint32_t selected{unique + 1};
    uint32_t count_base{selected + 1};
    uint32_t coefficient_base{count_base + kQueriesV12 + 1};
    uint32_t horner_base{coefficient_base + kQueriesV12 + 1};
    uint32_t output_base{horner_base + kQueriesV12 + 1};
    uint32_t write_base{output_base + kQueriesV12};
    uint32_t active{write_base + kQueriesV12};
    uint32_t end{active + 1};

    [[nodiscard]] constexpr uint32_t Candidate(uint32_t lane) const
    {
        return candidate_base + lane;
    }
    [[nodiscard]] constexpr uint32_t Bit(uint32_t bit) const
    {
        return bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t And(uint32_t step) const
    {
        return and_base + step;
    }
    [[nodiscard]] constexpr uint32_t Count(uint32_t count) const
    {
        return count_base + count;
    }
    [[nodiscard]] constexpr uint32_t Coefficient(uint32_t degree) const
    {
        return coefficient_base + degree;
    }
    [[nodiscard]] constexpr uint32_t Horner(uint32_t degree) const
    {
        return horner_base + degree;
    }
    [[nodiscard]] constexpr uint32_t Output(uint32_t query) const
    {
        return output_base + query;
    }
    [[nodiscard]] constexpr uint32_t Write(uint32_t query) const
    {
        return write_base + query;
    }
};

inline constexpr uint32_t kAirColumnsV12 = LayoutV12{}.end;
inline constexpr uint32_t kProductionNldeV12 = UINT32_C(1) << 24;
// Union bound:
// C(128,33) * (2*95/2^24)^33 < 2^-440.
inline constexpr uint32_t kProductionExhaustionBoundBitsV12 = 440;

struct QuerySamplerAirV12 {
    LayoutV12 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<gf::Fp3> source_candidates;
    std::vector<uint32_t> selected_indices;
    std::vector<uint32_t> selected_candidate_ordinals;
    uint32_t lane{0};
    uint32_t n_lde{0};
    uint32_t domain_bits{0};
    uint32_t selected_count{0};
    uint32_t constraints{0};
    uint32_t violations{0};
    uint32_t max_alg_degree{0};
    uint32_t verifier_owned_preprocessed_columns{0};
    uint32_t proof_owned_preprocessed_columns{0};
    bool source_candidate_vector_shape_canonical{false};
    bool full_limb_canonicity_constrained{false};
    bool index_range_constrained{false};
    bool first_distinct_order_constrained{false};
    bool uniqueness_constrained{false};
    bool exact_q96_exhaustion_constrained{false};
    bool selected_outputs_constrained{false};
    bool recursive_safe_source_equality_consumed{false};
    bool valid{false};
    std::string note;
};

/**
 * Native protocol selection. `squeezed_lanes` is exactly 3*128 canonical
 * base-field lanes from the typed V12 SAFE SqueezeQueryVector call.
 */
[[nodiscard]] bool SelectFirstDistinctV12(
    const std::vector<gf::Fp>& squeezed_lanes,
    uint32_t n_lde, std::vector<uint32_t>& selected_indices,
    std::vector<uint32_t>* selected_ordinals = nullptr,
    std::string* why = nullptr);

/**
 * Build the executable selection AIR. On bounded exhaustion the function
 * returns false but leaves `out` populated with a nonzero terminal
 * constraint violation so tests can exhibit the rejected witness.
 */
[[nodiscard]] bool BuildQuerySamplerAirV12(
    uint32_t lane, uint32_t n_lde,
    const std::vector<gf::Fp>& squeezed_lanes,
    QuerySamplerAirV12& out, std::string* why = nullptr);

[[nodiscard]] bool ValidateQuerySamplerAirV12(
    uint32_t lane, uint32_t n_lde,
    const std::vector<gf::Fp>& squeezed_lanes,
    const QuerySamplerAirV12& air,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountQuerySamplerViolationsV12(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

[[nodiscard]] bool SameQuerySamplerAirV12(
    const QuerySamplerAirV12& left,
    const QuerySamplerAirV12& right);

inline constexpr bool kWithoutReplacementSamplerAirExecutableV12 = true;
inline constexpr bool
    kWithoutReplacementSamplerRecursiveSourceBindingV12 = false;
inline constexpr bool kWithoutReplacementSamplerSoleProductionSourceV12 =
    false;

static_assert(kCandidatesV12 > kQueriesV12);
static_assert((kTraceRowsV12 & (kTraceRowsV12 - 1)) == 0);
static_assert(kAirColumnsV12 == 562);
static_assert(!kWithoutReplacementSamplerSoleProductionSourceV12);

} // namespace matmul::v4::rc::stage3_safe_v12_query_sampler

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_QUERY_SAMPLER_H
