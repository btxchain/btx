// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_SELECTION_FUSED_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_SELECTION_FUSED_JOIN_H

#include <matmul/matmul_v4_rc_stage3_v13_occurrence_manifest.h>
#include <matmul/matmul_v4_rc_stage3_v13_selection_query_air.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v14_selection_fused_join {

namespace aq = air_quotient;
namespace bridge = stage3_safe_v12_recursive_bridge;
namespace gf = gkr_field;
namespace occurrence = stage3_v13_occurrence_manifest;
namespace selection = stage3_v13_selection_query_air;

inline constexpr uint16_t kFusedSelectionJoinVersionV1 = 1;

enum class EdgeRoleV1 : uint8_t {
    OodCandidate = 1,
    QueryCandidate = 2,
};

struct EdgeV1 {
    EdgeRoleV1 role{EdgeRoleV1::OodCandidate};
    uint32_t event{0};
    uint32_t ordinal{0};
    uint32_t coordinate{0};
    uint32_t source_row{0};
    uint32_t source_column{0};
    uint32_t destination_row{0};
    uint32_t destination_column{0};
    uint32_t join_row{0};
    uint32_t carry_column{0};
    uint32_t source_selector_column{0};
    uint32_t destination_selector_column{0};
    uint32_t join_selector_column{0};

    friend bool operator==(const EdgeV1&, const EdgeV1&) = default;
};

struct LayoutV1 {
    uint32_t v14_base{0};
    uint32_t v14_columns{
        bridge::kTypedSafeDirectParentColumnsV14};
    uint32_t selection_base{v14_columns};
    uint32_t selection_columns{
        selection::LayoutV1{}.End()};
    uint32_t edge_value{selection_base + selection_columns};
    uint32_t edge_role{edge_value + 1};
    uint32_t edge_event{edge_role + 1};
    uint32_t edge_ordinal{edge_event + 1};
    uint32_t edge_coordinate{edge_ordinal + 1};
    uint32_t edge_multiplicity{edge_coordinate + 1};
    uint32_t edge_active{edge_multiplicity + 1};
    uint32_t expected_role{edge_active + 1};
    uint32_t expected_event{expected_role + 1};
    uint32_t expected_ordinal{expected_event + 1};
    uint32_t expected_coordinate{expected_ordinal + 1};
    uint32_t expected_multiplicity{expected_coordinate + 1};
    uint32_t carry_base{0};
    uint32_t source_selector_base{0};
    uint32_t destination_selector_base{0};
    uint32_t join_selector_base{0};
    uint32_t dependent_zero{0};
    uint32_t end{0};

    [[nodiscard]] uint32_t Selection(uint32_t column) const
    {
        return selection_base + column;
    }
    [[nodiscard]] uint32_t Carry(uint32_t edge) const
    {
        return carry_base + edge;
    }
    [[nodiscard]] uint32_t SourceSelector(uint32_t edge) const
    {
        return source_selector_base + edge;
    }
    [[nodiscard]] uint32_t DestinationSelector(uint32_t edge) const
    {
        return destination_selector_base + edge;
    }
    [[nodiscard]] uint32_t JoinSelector(uint32_t edge) const
    {
        return join_selector_base + edge;
    }
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1(uint32_t edge_count);

struct ScheduleV1 {
    occurrence::ManifestV1 manifest;
    std::vector<EdgeV1> edges;
    std::vector<uint32_t> v14_event_row;
    uint32_t ood_edges{0};
    uint32_t query_edges{0};
    uint32_t trace_rows{0};
    uint32_t query_count{0};
    uint32_t n_lde{0};
    bool exact_manifest_rebuilt{false};
    bool exact_k2_multiplicity{false};
    bool exact_q192_multiplicity{false};
    bool ordinary_same_parent_cells{false};
    bool valid{false};
    std::string note;
};

/**
 * Rebuild the production schedule and one fused constraint system from
 * public data only. V14 remains at columns [0,575); the complete selection
 * chip is shifted directly after it. Every edge transports one actual V14
 * Output cell to one actual selection input cell through a constant ordinary
 * carry inside the SAME commitment. The row-tagged edge table makes role,
 * event address, ordinal, coordinate and multiplicity proof-owned and
 * verifier-constrained.
 */
[[nodiscard]] bool BuildConstraintSystemV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    aq::AirConstraintSystem<gf::Fp3>& out,
    LayoutV1& layout,
    ScheduleV1& schedule,
    std::string* why = nullptr);

struct ProductV1 {
    LayoutV1 layout{};
    ScheduleV1 schedule;
    alg_hash::Digest expected_transcript_commitment{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t violations{0};
    uint32_t max_alg_degree{0};
    bool v14_constraints_fused{false};
    bool selection_constraints_fused{false};
    bool ood_candidate_outputs_bound{false};
    bool query_candidate_outputs_bound{false};
    bool query_reduction_local_proof_tape_equality{false};
    bool actual_proof_tape_cells_bound{false};
    bool selected_z_to_derived_hash_bound{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(
    const occurrence::ManifestV1& manifest,
    const bridge::TypedSafeDirectParentProductV14& v14,
    const selection::ProductV1& selected);

struct ProofV1 {
    uint16_t version{kFusedSelectionJoinVersionV1};
    alg_hash::Digest program_root{};
    alg_hash::Digest transcript_commitment{};
    aq::AirQuotientRowsProof proof{};
    bool actual_proof_tape_cells_bound{false};
    bool selected_z_to_derived_hash_bound{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    const uint256& fs_seed,
    ProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const ProofV1& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kV14SelectionSameParentExecutableV1 = true;
inline constexpr bool kActualProofTapeCellsBoundV1 = false;
inline constexpr bool kSelectedZToDerivedHashBoundV1 = false;
inline constexpr bool kV14SelectionRecursiveAuthorityReadyV1 = false;

static_assert(!kActualProofTapeCellsBoundV1);
static_assert(!kSelectedZToDerivedHashBoundV1);
static_assert(!kV14SelectionRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v14_selection_fused_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V14_SELECTION_FUSED_JOIN_H
