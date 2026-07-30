// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_SELECTION_QUERY_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_SELECTION_QUERY_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_selection_query_air {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kSelectionQueryAirVersionV1 = 1;
inline constexpr uint32_t kOodCandidatesV1 = 4;
inline constexpr uint32_t kFp3CoordinatesV1 = 3;
inline constexpr uint32_t kCanonicalBitsV1 = 64;
inline constexpr uint32_t kCanonicalAndChunkV1 = 5;
inline constexpr uint32_t kCanonicalAndStepsV1 =
    (32 + kCanonicalAndChunkV1 - 1) / kCanonicalAndChunkV1;
inline constexpr uint32_t kSelectionRowV1 = 12;
inline constexpr uint32_t kQueryRowBaseV1 = 16;
inline constexpr uint32_t kProductionQueriesV1 =
    kRCFri3AlgNumQueries;
// The native V13 verifier forms n_lde = n_coeffs * 16 in uint32_t after
// checking n_coeffs <= UINT32_MAX / 16.  Hence the largest supported
// power-of-two LDE is 2^31.
inline constexpr uint32_t kMaxProtocolLdeV1 = uint32_t{1} << 31;

struct RawFp3V1 {
    std::array<uint64_t, kFp3CoordinatesV1> coordinate{};
};

struct InputV1 {
    // [0,1] are the fixed-K2 candidates for z1; [2,3] are those for z2.
    std::array<RawFp3V1, kOodCandidatesV1> ood_candidate{};
    // Ordinary proof-tape cells.  They are not preprocessed constants.
    RawFp3V1 proof_tape_z1{};
    RawFp3V1 proof_tape_z2{};
    // One ordinary V14 SAFE digest lane and proof-owned query-index cell per
    // query.  The wide native reduction ((c1 << 64) | c0) mod n_lde reduces
    // to the low log2(n_lde) bits of c0 for every admitted n_lde.
    std::vector<uint64_t> query_digest_lane0;
    std::vector<uint32_t> proof_query_index;
    uint32_t n_lde{0};
};

struct CellRefV1 {
    uint32_t column{0};
    uint32_t row{0};

    bool operator==(const CellRefV1&) const = default;
};

struct Fp3CellRefsV1 {
    std::array<CellRefV1, kFp3CoordinatesV1> coordinate{};

    bool operator==(const Fp3CellRefsV1&) const = default;
};

struct QueryCellRefsV1 {
    CellRefV1 v14_digest_lane0{};
    CellRefV1 reduced_index{};
    CellRefV1 proof_tape_index{};

    bool operator==(const QueryCellRefsV1&) const = default;
};

/**
 * Exact ordinary-cell seam for the future fused parent.  The map contains
 * no host acceptance booleans and no proof values installed as preprocessed
 * columns.  A same-parent join must equality-link:
 *
 *   V14 candidate outputs -> ood_candidate
 *   selected_z*            -> proof_tape_z*
 *   V14 query lane0        -> query[q].v14_digest_lane0
 *   proof QueryIndex       -> query[q].proof_tape_index
 */
struct CellMapV1 {
    std::array<Fp3CellRefsV1, kOodCandidatesV1> ood_candidate{};
    Fp3CellRefsV1 selected_z1{};
    Fp3CellRefsV1 selected_z2{};
    Fp3CellRefsV1 proof_tape_z1{};
    Fp3CellRefsV1 proof_tape_z2{};
    std::vector<QueryCellRefsV1> query;
};

struct LayoutV1 {
    uint32_t candidate_base{0}; // 4 * 3 stable ordinary cells
    uint32_t scalar_value{12};
    uint32_t scalar_bit_base{13};
    uint32_t scalar_and_base{77};
    uint32_t query_index{84};
    uint32_t proof_tape_query_index{85};

    uint32_t ext_zero_base{86};       // 4 candidates * 2 ext coords
    uint32_t ext_inverse_base{94};
    uint32_t has_extension_base{102}; // 4
    uint32_t diff_zero_base{106};     // z2 candidates * 3 coords
    uint32_t diff_inverse_base{112};
    uint32_t distinct_base{118};      // 2
    uint32_t acceptable_base{120};    // z1[2], z2[2]
    uint32_t selected_ordinal_base{124}; // z1,z2
    uint32_t selected_z1_base{126};   // 3
    uint32_t selected_z2_base{129};   // 3
    uint32_t proof_tape_z1_base{132}; // 3
    uint32_t proof_tape_z2_base{135}; // 3

    uint32_t scalar_active{138};
    uint32_t candidate_active{139};
    uint32_t query_active{140};
    uint32_t selection_active{141};
    uint32_t candidate_slot_base{142}; // 12 positional one-hot selectors
    uint32_t dependent_zero{154};

    [[nodiscard]] constexpr uint32_t Candidate(
        uint32_t candidate, uint32_t coordinate) const
    {
        return candidate_base +
            kFp3CoordinatesV1 * candidate + coordinate;
    }
    [[nodiscard]] constexpr uint32_t ScalarBit(uint32_t bit) const
    {
        return scalar_bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t ScalarAnd(uint32_t step) const
    {
        return scalar_and_base + step;
    }
    [[nodiscard]] constexpr uint32_t ExtZero(
        uint32_t candidate, uint32_t ext_coordinate) const
    {
        return ext_zero_base + 2 * candidate + ext_coordinate;
    }
    [[nodiscard]] constexpr uint32_t ExtInverse(
        uint32_t candidate, uint32_t ext_coordinate) const
    {
        return ext_inverse_base + 2 * candidate + ext_coordinate;
    }
    [[nodiscard]] constexpr uint32_t HasExtension(
        uint32_t candidate) const
    {
        return has_extension_base + candidate;
    }
    [[nodiscard]] constexpr uint32_t DiffZero(
        uint32_t z2_candidate, uint32_t coordinate) const
    {
        return diff_zero_base + 3 * z2_candidate + coordinate;
    }
    [[nodiscard]] constexpr uint32_t DiffInverse(
        uint32_t z2_candidate, uint32_t coordinate) const
    {
        return diff_inverse_base + 3 * z2_candidate + coordinate;
    }
    [[nodiscard]] constexpr uint32_t Distinct(
        uint32_t z2_candidate) const
    {
        return distinct_base + z2_candidate;
    }
    [[nodiscard]] constexpr uint32_t Acceptable(
        uint32_t pair, uint32_t ordinal) const
    {
        return acceptable_base + 2 * pair + ordinal;
    }
    [[nodiscard]] constexpr uint32_t SelectedOrdinal(
        uint32_t pair) const
    {
        return selected_ordinal_base + pair;
    }
    [[nodiscard]] constexpr uint32_t SelectedZ1(uint32_t coordinate) const
    {
        return selected_z1_base + coordinate;
    }
    [[nodiscard]] constexpr uint32_t SelectedZ2(uint32_t coordinate) const
    {
        return selected_z2_base + coordinate;
    }
    [[nodiscard]] constexpr uint32_t ProofTapeZ1(uint32_t coordinate) const
    {
        return proof_tape_z1_base + coordinate;
    }
    [[nodiscard]] constexpr uint32_t ProofTapeZ2(uint32_t coordinate) const
    {
        return proof_tape_z2_base + coordinate;
    }
    [[nodiscard]] constexpr uint32_t CandidateSlot(uint32_t slot) const
    {
        return candidate_slot_base + slot;
    }
    [[nodiscard]] constexpr uint32_t End() const
    {
        return dependent_zero + 1;
    }
};

struct ProductV1 {
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    CellMapV1 cell_map;
    uint32_t trace_rows{0};
    uint32_t query_count{0};
    uint32_t domain_bits{0};
    uint32_t violations{1};
    uint32_t max_alg_degree{0};
    uint32_t selected_z1_ordinal{0};
    uint32_t selected_z2_ordinal{0};

    bool candidates_ordinary{false};
    bool outputs_ordinary{false};
    bool canonical_goldilocks_constrained{false};
    bool first_acceptable_constrained{false};
    bool distinct_z2_constrained{false};
    bool local_tape_equality_cells_constrained{false};
    bool query_reduction_constrained{false};
    bool production_q192{false};
    bool actual_v14_output_cells_bound{false};
    bool actual_proof_tape_cells_bound{false};
    bool recursive_authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildConstraintSystemV1(
    uint32_t n_lde,
    uint32_t query_count,
    aq::AirConstraintSystem<gf::Fp3>& out,
    CellMapV1& cell_map,
    std::string* why = nullptr);

[[nodiscard]] ProductV1 BuildProductV1(
    const InputV1& input);

[[nodiscard]] uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_v13_selection_query_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_SELECTION_QUERY_AIR_H
