// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_NARROW_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_NARROW_H

#include <matmul/matmul_v4_rc_stage3_coupled_bank_stream.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * One execution of the reusable vertical verifier chip.  No child witness is
 * retained: lanes are scanned serially so peak width, rather than four-lane
 * mirrored width, determines the physical parent budget.
 */
struct RCStage3CoupledBankNarrowLane {
    uint32_t logical_child{0};
    uint32_t ordered_v5_lane{0};
    uint32_t active_hash_rows{0};
    uint32_t trace_rows{0};
    uint32_t hash_columns{0};
    uint32_t fold_bus_columns{0};
    uint32_t constraints{0};
    uint32_t fold_pairs{0};
    uint32_t violations{0};
    bool dual_envelope_accepted{false};
    bool current_row_opening{false};
    bool next_row_opening{false};
    bool trace_binding_opening{false};
    bool every_fold_opening{false};
    bool fold_hash_scalar_join{false};
    bool valid{false};
};

/**
 * Executable V1 width-compaction experiment for the two-child/four-ordered-
 * lane bank parent.
 *
 * The expensive current-row, next-row, trace-binding and fold Merkle paths
 * execute through one reusable 545-column chip.  The compact four-row
 * terminal relation proves repetition equality, child interval contiguity,
 * all eight SHA chaining words, and the 18-word parent export.  The terminal
 * trace is intentionally retained for differential mutation tests.
 * A 975-column scalar phase time-multiplexes all four V5 lanes, pins every
 * proof-derived current/next/fold/evaluation cell, and executes dual-OOD DEEP,
 * fold chaining and every child per-point quotient rule.  Its terminal cells
 * alias both OOD evaluation vectors.  The separate eight-column public
 * boundary maps every SHA-derived V5 challenge consumer.  Active phase rows
 * fit one 131,072-row schedule; the gated single-CS assembly is still open.
 *
 * This is not a recursive authority proof.  The phase constraint systems
 * have not yet been gated into one emitted parent, and the SHA transcript
 * derivation equations remain outside the boundary materialization.
 */
struct RCStage3CoupledBankNarrowExecution {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    std::vector<RCStage3CoupledBankNarrowLane> lanes;
    std::vector<uint256> child_proof_commitments;
    air_quotient::AirConstraintSystem<gkr_field::Fp3> terminal_cs;
    std::vector<std::vector<gkr_field::Fp3>> terminal_columns;
    air_quotient::AirConstraintSystem<gkr_field::Fp3> scalar_cs;
    std::vector<std::vector<gkr_field::Fp3>> scalar_columns;
    air_quotient::AirConstraintSystem<gkr_field::Fp3>
        v5_semantic_cs;
    std::vector<std::vector<gkr_field::Fp3>>
        v5_semantic_columns;
    std::array<uint32_t, 18> parent_output_words{};
    uint64_t scheduled_hash_active_rows{0};
    uint64_t scheduled_hash_rows{0};
    uint64_t combined_active_rows{0};
    uint32_t combined_trace_rows{0};
    uint32_t reusable_hash_columns{0};
    uint32_t reusable_fold_bus_columns{0};
    uint32_t terminal_bus_columns{0};
    uint32_t physical_column_target{0};
    uint32_t selected_full_parent_width{0};
    uint32_t unexecuted_family_column_reservation{0};
    uint32_t terminal_violations{0};
    uint32_t scalar_rows{0};
    uint32_t scalar_columns_count{0};
    uint32_t scalar_constraints{0};
    uint32_t scalar_violations{0};
    uint32_t scalar_eval_z1_column_base{0};
    uint32_t scalar_eval_z2_column_base{0};
    uint32_t scalar_terminal_column_base{0};
    uint32_t scalar_parent_column_base{0};
    uint32_t v5_semantic_cells{0};
    uint32_t v5_semantic_rows{0};
    uint32_t v5_semantic_columns_count{0};
    uint32_t v5_semantic_violations{0};
    uint256 v5_sha_boundary_commitment{};
    bool four_ordered_lanes_executed{false};
    bool exact_dual_transcripts_checked{false};
    bool hash_families_complete{false};
    bool fold_scalar_bus_complete{false};
    bool terminal_relation_executable{false};
    bool terminal_values_proof_derived{false};
    bool deep_dual_ood_executable{false};
    bool per_point_quotient_executable{false};
    bool scalar_openings_proof_derived{false};
    bool scalar_terminal_same_trace{false};
    bool v5_sha_semantic_boundary_executable{false};
    bool all_v5_consumer_cells_mapped{false};
    bool vertical_width_under_cap{false};
    bool selected_full_width_under_cap{false};
    bool combined_trace_within_selected{false};
    bool hash_terminal_single_parent_proof{false};
    bool complete_recursive_parent{false};
    bool parent_proof_emitted{false};
    bool consensus_authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] RCStage3CoupledBankNarrowExecution
BuildRCStage3CoupledBankNarrowExecution(
    const std::vector<
        air_quotient::AirConstraintSystem<gkr_field::Fp3>>& child_css,
    const std::vector<air_recurse::DualAlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    const std::vector<uint32_t>& child_output_column_bases);

struct RCStage3CoupledBankUnifiedParent {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    air_quotient::AirConstraintSystem<gkr_field::Fp3> parent_cs;
    std::vector<std::vector<gkr_field::Fp3>> parent_columns;
    RCStage3CoupledBankStreamDualIntervalAirProof parent_proof;
    std::array<uint32_t, 18> parent_output_words{};
    uint256 v5_sha_boundary_commitment{};
    uint256 parent_fs_seed{};
    uint32_t local_phase_columns{0};
    uint32_t fixed_columns{0};
    uint32_t selector_columns{0};
    uint32_t carry_columns{0};
    uint32_t parent_columns_count{0};
    uint32_t parent_rows{0};
    uint32_t parent_constraints{0};
    uint32_t parent_max_degree{0};
    uint32_t quotient_len{0};
    uint32_t proof_coefficients{0};
    uint32_t proof_lde{0};
    uint64_t estimated_lde_cells{0};
    uint64_t prove_micros{0};
    uint64_t verify_micros{0};
    uint32_t violations{0};
    bool one_selector_scheduled_trace{false};
    bool exact_phase_transitions{false};
    bool fixed_columns_publicly_pinned{false};
    bool fs_public_boundary_bound{false};
    bool scalar_terminal_output_carried{false};
    bool all_phase_outputs_same_trace{false};
    bool under_selected_width{false};
    bool proof_resource_feasible{false};
    bool parent_proof_emitted{false};
    bool parent_proof_verified{false};
    bool consensus_authority{false};
    bool valid{false};
    std::string note;
};

struct RCStage3CoupledBankStreamingLdePlan {
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t lde_rows{0};
    uint32_t tile_rows{0};
    uint32_t passes{0};
    uint64_t dense_lde_cells{0};
    uint64_t peak_live_cells{0};
    uint64_t external_work_cells{0};
    bool column_store_required{false};
    bool two_pass_row_merkle_required{false};
    bool quotient_row_tiles_executable{false};
    bool fri_fold_tiles_executable{false};
    bool transcript_equivalence_proven{false};
    bool under_dense_cell_screen{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] RCStage3CoupledBankStreamingLdePlan
PlanRCStage3CoupledBankStreamingLde(
    uint32_t trace_rows,
    uint32_t trace_columns,
    uint32_t lde_rows,
    uint32_t tile_rows = 4096);

[[nodiscard]] RCStage3CoupledBankUnifiedParent
BuildRCStage3CoupledBankUnifiedParent(
    const std::vector<
        air_quotient::AirConstraintSystem<gkr_field::Fp3>>& child_css,
    const std::vector<air_recurse::DualAlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    const std::vector<uint32_t>& child_output_column_bases);

inline constexpr bool
    kRCStage3CoupledBankNarrowHashFamiliesExecutable = true;
inline constexpr bool
    kRCStage3CoupledBankNarrowCompleteRecursiveParent = false;
inline constexpr bool
    kRCStage3CoupledBankNarrowConsensusAuthority = false;

static_assert(kRCStage3CoupledBankNarrowHashFamiliesExecutable);
static_assert(!kRCStage3CoupledBankNarrowCompleteRecursiveParent);
static_assert(!kRCStage3CoupledBankNarrowConsensusAuthority);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_NARROW_H
