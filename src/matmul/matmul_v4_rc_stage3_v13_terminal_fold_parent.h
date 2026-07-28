// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_TERMINAL_FOLD_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_TERMINAL_FOLD_PARENT_H

#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace matmul::v4::rc::stage3_v13_terminal_fold_parent {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace composer = stage3_air_parent_composer;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kFinalValueCoordinatesV1 = 3;
inline constexpr uint32_t kTerminalRootCoordinatesV1 = 4;
inline constexpr uint32_t kU32LimbsPerFieldV1 = 2;
inline constexpr uint32_t kFinalValueLimbsV1 =
    kFinalValueCoordinatesV1 * kU32LimbsPerFieldV1;
inline constexpr uint32_t kTerminalRootLimbsV1 =
    kTerminalRootCoordinatesV1 * kU32LimbsPerFieldV1;

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    bool operator==(const CellRefV1&) const = default;
};

/**
 * Verifier-owned shape of the terminal constant FRI layer.  It is derived
 * from the public proof-tape shape and the fixed protocol blowup only.
 * Neither final_value nor the claimed terminal root enters this plan.
 */
struct PublicPlanV1 {
    uint16_t version{kVersionV1};
    uint32_t blowup{0};
    uint32_t fold_count{0};
    uint32_t real_rows{0};
    uint32_t trace_rows{0};
    uint32_t internal_edges{0};
    mf::HashLayoutV1 hash{};
    uint256 plan_root{};
    bool proof_values_excluded{false};
    bool exact_tree_schedule{false};
    bool valid{false};
    std::string note;

};

[[nodiscard]] PublicPlanV1 BuildPublicPlanV1(
    const tape::PublicShapeV1& shape);

struct LayoutV1 {
    mf::HashLayoutV1 hash{};
    uint32_t final_value_base{0};
    uint32_t final_value_limb_base{0};
    uint32_t final_value_bit_base{0};
    uint32_t terminal_root_limb_base{0};
    uint32_t terminal_root_bit_base{0};
    uint32_t edge_carrier_base{0};
    uint32_t leaf_selector{0};
    uint32_t node_selector{0};
    uint32_t padding_selector{0};
    uint32_t root_selector{0};
    uint32_t leaf_index{0};
    uint32_t edge_source_selector_base{0};
    uint32_t edge_sink_selector_base{0};
    uint32_t acceptance{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t FinalValue(uint32_t coordinate) const
    {
        return final_value_base + coordinate;
    }
    [[nodiscard]] uint32_t FinalValueLimb(
        uint32_t coordinate, uint32_t limb) const
    {
        return final_value_limb_base +
            coordinate * kU32LimbsPerFieldV1 + limb;
    }
    [[nodiscard]] uint32_t FinalValueBit(
        uint32_t coordinate, uint32_t bit) const
    {
        return final_value_bit_base + coordinate * 64 + bit;
    }
    [[nodiscard]] uint32_t TerminalRootLimb(
        uint32_t coordinate, uint32_t limb) const
    {
        return terminal_root_limb_base +
            coordinate * kU32LimbsPerFieldV1 + limb;
    }
    [[nodiscard]] uint32_t TerminalRootBit(
        uint32_t coordinate, uint32_t bit) const
    {
        return terminal_root_bit_base + coordinate * 64 + bit;
    }
    [[nodiscard]] uint32_t EdgeCarrier(
        uint32_t edge, uint32_t coordinate) const
    {
        return edge_carrier_base +
            edge * kTerminalRootCoordinatesV1 + coordinate;
    }
    [[nodiscard]] uint32_t EdgeSourceSelector(
        uint32_t edge) const
    {
        return edge_source_selector_base + edge;
    }
    [[nodiscard]] uint32_t EdgeSinkSelector(
        uint32_t edge) const
    {
        return edge_sink_selector_base + edge;
    }
};

struct AbiConsumerRefsV1 {
    std::array<CellRefV1, kFinalValueLimbsV1> final_value{};
    std::array<CellRefV1, kTerminalRootLimbsV1> terminal_root{};
};

struct OutputRefsV1 {
    CellRefV1 acceptance{};
    std::array<CellRefV1, kTerminalRootLimbsV1> terminal_root{};
};

/**
 * Executable terminal-tree child.  Every Poseidon input, every internal
 * child-to-parent edge, and the final root decomposition is constrained in
 * this CS.  ABI values remain ordinary cells exported through `abi_consumers`
 * for literal same-parent aliasing to the canonical proof tape.
 */
struct ProductV1 {
    PublicPlanV1 plan{};
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    AbiConsumerRefsV1 abi_consumers{};
    OutputRefsV1 outputs{};
    uint64_t violations{UINT64_MAX};
    bool public_plan_rebuilt{false};
    bool all_hash_inputs_constrained{false};
    bool every_internal_edge_constrained{false};
    bool final_value_decomposition_constrained{false};
    bool terminal_root_decomposition_constrained{false};
    bool no_proof_values_preprocessed{false};
    bool actual_proof_tape_aliased{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(
    const PublicPlanV1& plan,
    const abi::DecodedV1& decoded);

struct ParentAliasAttachmentV1 {
    uint16_t version{kVersionV1};
    uint32_t original_columns{0};
    uint32_t appended_carriers{0};
    uint32_t literal_aliases{0};
    uint32_t final_value_aliases{0};
    uint32_t terminal_root_aliases{0};
    uint32_t constraints{0};
    uint64_t violations{UINT64_MAX};
    std::array<CellRefV1, kFinalValueLimbsV1>
        tape_final_value{};
    std::array<CellRefV1, kTerminalRootLimbsV1>
        tape_terminal_root{};
    AbiConsumerRefsV1 terminal_consumers{};
    OutputRefsV1 terminal_outputs{};
    bool actual_tape_value_cells_referenced{false};
    bool actual_terminal_cells_referenced{false};
    bool aliases_are_ordinary_columns{false};
    bool selectors_only_preprocessed{false};
    bool cross_row_transport_constrained{false};
    bool global_r0_pending{true};
    bool valid{false};
    std::string note;
};

struct LiteralAliasAttachmentV1 {
    uint32_t original_columns{0};
    uint32_t literal_aliases{0};
    uint32_t appended_carriers{0};
    uint32_t constraints{0};
    uint64_t violations{UINT64_MAX};
    bool endpoints_ordinary{false};
    bool selectors_only_preprocessed{false};
    bool cross_row_transport_constrained{false};
    bool global_r0_pending{true};
    bool valid{false};
    std::string note;
};

/**
 * Primitive used by the production tape join: constrain exact equality of
 * arbitrary ordinary cells, even when the endpoints occupy unrelated rows.
 * It appends one transition-carried ordinary value plus verifier-owned
 * source/sink selectors per alias.  This function is intentionally exposed
 * so a bounded proof-level canary exercises the identical relation.
 */
[[nodiscard]] bool AppendLiteralAliasesV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const std::vector<std::pair<CellRefV1, CellRefV1>>& aliases,
    LiteralAliasAttachmentV1& out,
    std::string* why = nullptr);

/**
 * Append exact cross-row equality carriers between an already-resident V13
 * proof-tape child and terminal-tree child.  This must run before the parent
 * creates its one global R0 row commitment.
 */
[[nodiscard]] bool AppendProofTapeAliasesV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const tape::ProductV1& tape_product,
    const composer::ChildAttachmentV1& tape_attachment,
    const ProductV1& terminal_product,
    const composer::ChildAttachmentV1& terminal_attachment,
    ParentAliasAttachmentV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kRecursiveConsumptionV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kRecursiveConsumptionV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_terminal_fold_parent

#endif
