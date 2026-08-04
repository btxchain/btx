// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_DIRECT_PARENT_SPINE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_DIRECT_PARENT_SPINE_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_recursive_provenance_join.h>
#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_program_bridge.h>
#include <matmul/matmul_v4_rc_stage3_temporal_induction.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::direct_parent_spine {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kDirectParentSpineVersionV1 = 1;
inline constexpr uint32_t kDirectParentSpineArityV1 = 2;

/**
 * The verifier-reconstructed statement for one receipt child.  Roots are
 * transported as eight little-endian u32 cells, never as one Goldilocks
 * field cell.  `local_q_per_query` is reconstructed from the already
 * verified child receipt; it is not supplied as a free parent witness.
 */
struct ReceiptStatementV1 {
    uint32_t receipt_ordinal{0};
    uint256 source_identity{};
    uint256 query_schedule{};
    uint256 exact_set_manifest_root{};
    uint256 statement_root{};
    uint256 receipt_root{};
    std::vector<uint32_t> query_indices;
    std::vector<gf::Fp3> source_parent_q;
    std::vector<gf::Fp3> local_q_per_query;
    std::vector<uint32_t> program_ordinals;
};

/**
 * Complete public statement of the arity-two ownership relation.
 *
 * The two program-ordinal vectors must be individually sorted and their
 * union must be exactly [0,total_program_ordinals).  This is deliberately an
 * exact-set statement, rather than a count-only statement.
 */
struct DirectParentStatementV1 {
    uint16_t version{kDirectParentSpineVersionV1};
    uint32_t total_program_ordinals{0};
    uint256 source_identity{};
    uint256 query_schedule{};
    uint256 exact_set_manifest_root{};
    std::vector<uint32_t> query_indices;
    std::vector<gf::Fp3> source_parent_q;
    std::array<ReceiptStatementV1, kDirectParentSpineArityV1> receipts;
};

/**
 * Cells exported by the source verifier and the two child-receipt verifiers.
 * They have the same shape as the statement, but are kept separate so an AIR
 * equality (not a host-language comparison) owns every terminal.
 */
struct DirectParentTerminalExportsV1 {
    uint256 source_identity{};
    uint256 query_schedule{};
    uint256 exact_set_manifest_root{};
    std::vector<uint32_t> query_indices;
    std::vector<gf::Fp3> source_parent_q;
    std::array<ReceiptStatementV1, kDirectParentSpineArityV1> receipts;
};

struct RootU32ColumnsV1 {
    std::array<uint32_t, 8> limb{};
};

struct CommonColumnsV1 {
    uint32_t row_kind{0};
    uint32_t active{0};
    uint32_t query_counter{0};
    uint32_t coverage_counter{0};
};

struct SourceColumnsV1 {
    RootU32ColumnsV1 source_identity;
    RootU32ColumnsV1 query_schedule;
    RootU32ColumnsV1 exact_set_manifest_root;
    uint32_t query_index{0};
    uint32_t parent_q{0};
};

struct ReceiptColumnsV1 {
    RootU32ColumnsV1 source_identity;
    RootU32ColumnsV1 query_schedule;
    RootU32ColumnsV1 exact_set_manifest_root;
    RootU32ColumnsV1 statement_root;
    RootU32ColumnsV1 receipt_root;
    uint32_t query_index{0};
    uint32_t source_parent_q{0};
    uint32_t local_q{0};
    uint32_t manifest_present{0};
    uint32_t receipt_ordinal{0};
    uint32_t receipt_position{0};
    uint32_t program_ordinal{0};
};

/**
 * References to terminal columns already resident in a normalized parent.
 * Passing this structure to AppendDirectParentSpineV1 reuses these columns;
 * passing nullptr installs a public/preprocessed fallback copy.
 *
 * Reusing these references is only "direct child aliasing" after the caller
 * has appended the child-verifier AIR that owns them.  This module exposes
 * that integration residual explicitly and never claims it by itself.
 */
struct TerminalColumnRefsV1 {
    CommonColumnsV1 common;
    SourceColumnsV1 source;
    std::array<ReceiptColumnsV1, kDirectParentSpineArityV1> receipts;
};

struct DirectParentSpineLayoutV1 {
    uint32_t original_columns{0};
    uint32_t terminal_rows{0};
    uint32_t query_rows{0};
    uint32_t manifest_rows{0};
    uint32_t padding_rows{0};
    TerminalColumnRefsV1 actual;
    TerminalColumnRefsV1 expected;
    uint32_t is_query{0};
    uint32_t is_manifest{0};
    uint32_t is_padding{0};
    uint32_t manifest_first{0};
    uint32_t manifest_last{0};
    uint32_t manifest_has_next{0};
    uint32_t end_column{0};
};

struct DirectParentSpineAppendV1 {
    bool valid{false};
    bool statement_exact_set{false};
    bool statement_q_partition{false};
    bool terminal_row_equality_constrained{false};
    bool ordered_receipt_coverage_constrained{false};
    bool source_identity_constrained{false};
    bool query_schedule_constrained{false};
    bool source_q_constrained{false};
    bool local_q_join_constrained{false};
    bool padding_zero_constrained{false};
    bool all_actual_inputs_verifier_owned{false};
    bool preprocessed_fallback{false};
    bool actual_columns_reused{false};
    bool direct_alias_capable{true};
    /** False until the real child-verifier columns are wired to `actual`. */
    bool direct_child_aliases{false};
    /** False until this combined CS is proved and re-entered by its parent. */
    bool recursively_consumed{false};
    bool no_free_binding_or_q_witness{false};
    DirectParentSpineLayoutV1 layout;
    std::string note;
};

[[nodiscard]] bool ValidateDirectParentStatementV1(
    const DirectParentStatementV1& statement,
    std::string* why = nullptr);

/**
 * Append the ownership relation to an existing parent CS and witness.
 *
 * With `direct_actual == nullptr`, actual terminal exports and the
 * verifier-reconstructed expected table are both installed as canonical
 * public/preprocessed columns.  This is executable and has no free q/binding
 * witness, but is intentionally labelled `preprocessed_fallback` and not
 * direct recursion.
 *
 * With non-null `direct_actual`, every referenced column must already exist,
 * be unique, and contain the supplied terminal exports.  Only the expected
 * public table/selectors are appended.  This makes the construction directly
 * appendable to a normalized child verifier without adding another proof.
 */
[[nodiscard]] bool AppendDirectParentSpineV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const DirectParentStatementV1& statement,
    const DirectParentTerminalExportsV1& terminals,
    DirectParentSpineAppendV1& out,
    const TerminalColumnRefsV1* direct_actual = nullptr,
    std::string* why = nullptr);

// -------------------------------------------------------------------------
// Canonical named-consumer spine for recursive provenance.
//
// This is deliberately narrower than full endpoint semantic closure.  It
// makes every named consumer an actual, fixed cell of one canonical
// constraint-bytecode program, but does not upgrade the 31 endpoint families
// whose original episode/coupled relation program still lacks an executable
// output recipe.

inline constexpr uint16_t
    kCanonicalProvenanceConsumerVersionV1 = 1;
inline constexpr uint32_t
    kCanonicalProvenanceConsumerRootWordsV1 = 8;
inline constexpr uint32_t
    kCanonicalProvenanceConsumerWordBitsV1 = 32;

enum class CanonicalProvenanceConsumerRowKindV1 : uint32_t {
    Padding = 0,
    Role = 1,
    Endpoint = 2,
    TemporalEvent = 3,
};

struct CanonicalProvenanceConsumerLayoutV1 {
    uint32_t base{0};
    uint32_t active{0};
    uint32_t row_kind{0};
    uint32_t role{0};
    uint32_t endpoint{0};
    uint32_t event_kind{0};
    uint32_t producer{0};
    uint32_t consumer{0};
    uint32_t producer_position{0};
    uint32_t consumer_position{0};
    uint32_t ordinal{0};
    uint32_t family_index{0};
    uint32_t relation_column{0};
    uint32_t route_status{0};
    std::array<uint32_t, 8> program_external{};
    std::array<uint32_t, 8> program_recursive{};
    std::array<uint32_t, 8> root_word{};
    uint32_t root_bits_base{0};
    uint32_t expected_base{0};
    uint32_t end_column{0};

    bool operator==(
        const CanonicalProvenanceConsumerLayoutV1&) const = default;
};

struct CanonicalProvenanceConsumerPlanV1 {
    uint16_t version{kCanonicalProvenanceConsumerVersionV1};
    uint32_t parent_rows{0};
    uint32_t parent_original_columns{0};
    uint32_t active_rows{0};
    uint32_t role_rows{0};
    uint32_t endpoint_rows{0};
    uint32_t temporal_rows{0};
    CanonicalProvenanceConsumerLayoutV1 layout;
    uint256 semantic_program_bridge_commitment{};
    uint256 bytecode_program_root{};
    alg_hash::Digest bytecode_program_alg_root{};
    uint256 consumer_schedule_root{};
    uint256 fixed_alias_schedule_commitment{};
    bool exact_14_roles{false};
    bool exact_52_endpoints{false};
    bool exact_temporal_schedule{false};
    bool canonical_program_table{false};
    bool valid{false};

    bool operator==(
        const CanonicalProvenanceConsumerPlanV1&) const = default;
};

struct CanonicalProvenanceConsumerAttachmentV1 {
    CanonicalProvenanceConsumerPlanV1 plan;
    recursive_provenance_join::
        RecursiveProvenanceParentAliasAttachmentV1 alias;
    uint32_t constraints_added{0};
    uint32_t preprocessing_columns_added{0};
    uint32_t violations{UINT32_MAX};
    bool independently_pinned_plan_match{false};
    bool root_words_are_canonical_u32{false};
    bool root_words_bit_constrained{false};
    bool all_consumer_addresses_program_allocated{false};
    bool temporal_event_schedule_bound{false};
    bool no_free_consumer_root_witness{false};
    /**
     * True only in the narrow sense that every named consumer is an input
     * cell of this canonical router ProgramTable and is equality-linked to
     * the corresponding source cell in the same parent proof.
     */
    bool named_consumer_semantics_constrained{false};
    /** Still false for the 31 original relation-program output gaps. */
    bool underlying_relation_program_semantics_complete{false};
    bool verifier_output_semantics_constrained{false};
    bool complete_child_acceptance_in_same_parent{false};
    bool recursive_authority{false};
    bool valid{false};
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Derive the exact parent-relative bytecode program, consumer cells, and
 * alias schedule.  `verifier_sources` contains only canonical source
 * addresses; every named-consumer address must be unset.  The returned plan
 * is intended to be pinned by the enclosing parent program/statement before
 * proof verification.
 */
[[nodiscard]] CanonicalProvenanceConsumerPlanV1
BuildCanonicalProvenanceConsumerPlanV1(
    const recursive_provenance_join::
        RecursiveProvenanceShapeV1& shape,
    const recursive_provenance_join::
        RecursiveProvenanceParentAliasRefsV1& verifier_sources);

/**
 * Append the canonical consumer ProgramTable, materialize its root inputs
 * from strict-u32 source cells, and append the complete provenance equality
 * bus.  The expected plan must be obtained independently; recomputing it from
 * prover-chosen addresses would forfeit fixed-offset binding.
 */
[[nodiscard]] bool AppendCanonicalProvenanceConsumerSpineV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const recursive_provenance_join::
        RecursiveProvenanceShapeV1& shape,
    const recursive_provenance_join::
        RecursiveProvenanceParentAliasRefsV1& verifier_sources,
    const CanonicalProvenanceConsumerPlanV1& expected_plan,
    CanonicalProvenanceConsumerAttachmentV1& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::direct_parent_spine

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_DIRECT_PARENT_SPINE_H
