// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_UNIFIED_VERIFIER_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_UNIFIED_VERIFIER_AIR_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_verifier.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace dj = stage3_multirow_v11_decoder_join;
namespace dvm = stage3_multirow_v11_deep_vm;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace np = stage3_multirow_v11_normalized_program;
namespace pj = stage3_multirow_v11_parent_join;
namespace rv = stage3_multirow_v11_recursive_verifier;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kQ96QueriesV1 = 96;
inline constexpr uint32_t kTraceRowsCapV1 = 1U << 20;
inline constexpr uint32_t kLdeRowsCapV1 = 1U << 24;
inline constexpr uint32_t kDecoderChallengeColumnsV1 = 4;
inline constexpr uint32_t kDecoderHornerStagesV1 = 4;
inline constexpr uint32_t kDecoderHornerAuxColumnsV1 =
    dj::kDecoderJoinBusLanesV1 * 2 *
    kDecoderHornerStagesV1;

enum class PhaseV1 : uint8_t {
    ParentJoin = 0,
    MerkleHash = 1,
    MerkleFold = 2,
    DeepVm = 3,
    Decoder = 4,
    Count = 5,
};

inline constexpr uint32_t kPhasesV1 =
    static_cast<uint32_t>(PhaseV1::Count);

struct PhaseShapeV1 {
    PhaseV1 phase{PhaseV1::ParentJoin};
    uint32_t first_row{0};
    uint32_t rows{0};
    uint32_t columns{0};
    uint32_t constraints{0};
    uint32_t preprocessed_columns{0};
    uint32_t max_degree{0};
};

struct LayoutV1 {
    uint32_t data_base{0};
    uint32_t data_columns{0};
    uint32_t phase_tag_base{0};
    uint32_t phase_first_base{0};
    uint32_t phase_last_base{0};
    uint32_t phase_transition_base{0};
    uint32_t active{0};
    /** Ordinary one-cell output: one iff this entire unified relation holds. */
    uint32_t acceptance{0};
    uint32_t expected_preprocessed_base{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t PhaseTag(PhaseV1 phase) const
    {
        return phase_tag_base +
            static_cast<uint32_t>(phase);
    }
    [[nodiscard]] uint32_t PhaseFirst(PhaseV1 phase) const
    {
        return phase_first_base +
            static_cast<uint32_t>(phase);
    }
    [[nodiscard]] uint32_t PhaseLast(PhaseV1 phase) const
    {
        return phase_last_base +
            static_cast<uint32_t>(phase);
    }
    [[nodiscard]] uint32_t PhaseTransition(PhaseV1 phase) const
    {
        return phase_transition_base +
            static_cast<uint32_t>(phase);
    }
};

struct ProductV1 {
    uint16_t version{kVersionV1};
    rv::QueryRangeV1 range{};
    pj::ProductV1 parent_join{};
    mf::ShardProductV1 merkle_fold{};
    dvm::ProductV1 deep_vm{};
    dj::ProductV1 decoder{};
    LayoutV1 layout{};
    std::array<PhaseShapeV1, kPhasesV1> phases{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    uint32_t commitment_coefficients{0};
    uint64_t commitment_lde_rows{0};
    uint32_t expected_preprocessed_columns{0};
    uint64_t materialized_trace_cells{0};
    uint64_t violations{0};
    bool exact_q96_range{false};
    bool all_five_phases_executable{false};
    bool vertical_max_width_layout{false};
    bool one_hot_row_scheduler_constrained{false};
    bool local_boundary_kinds_preserved{false};
    bool every_phase_preprocessed_pin_r0_bound{false};
    bool acceptance_ordinary_witness{false};
    bool acceptance_unique{false};
    bool whole_verifier_acceptance_constrained{false};
    alg_hash::Digest acceptance_program_root{};
    uint32_t acceptance_program_constraints{0};
    bool acceptance_constraints_canonical_bytecode{false};
    bool acceptance_program_root_recomputed{false};
    alg_hash::Digest scheduler_program_root{};
    uint32_t scheduler_program_constraints{0};
    bool scheduler_constraints_canonical_bytecode{false};
    bool scheduler_program_root_recomputed{false};
    alg_hash::Digest parent_join_program_root{};
    uint32_t parent_join_program_constraints{0};
    bool parent_join_constraints_canonical_bytecode{false};
    bool parent_join_program_root_recomputed{false};
    uint256 parent_join_statement_manifest_r0_root{};
    uint32_t parent_join_statement_manifest_r0_columns{0};
    bool parent_join_proof_tape_cells_ordinary{false};
    bool parent_join_proof_tape_fixed_offsets{false};
    bool parent_join_digest_claims_poseidon_bound{false};
    bool parent_join_statement_root_r0_bound{false};
    /** True only when all per-proof transcript/value cells have left R0. */
    bool parent_join_r0_statement_manifest_only{false};
    bool parent_join_cs_independent_of_child_witness{false};
    alg_hash::Digest merkle_hash_program_root{};
    uint32_t merkle_hash_program_constraints{0};
    bool merkle_hash_constraints_canonical_bytecode{false};
    bool merkle_hash_program_root_recomputed{false};
    uint32_t merkle_hash_statement_manifest_r0_columns{0};
    uint32_t merkle_hash_proof_tape_cells{0};
    bool merkle_hash_proof_tape_cells_ordinary{false};
    /** Input/output lane offsets are fixed by HashLayoutV1, never witnessed. */
    bool merkle_hash_proof_tape_fixed_lane_offsets{false};
    bool merkle_hash_io_poseidon_bound{false};
    bool merkle_hash_r0_statement_manifest_only{false};
    bool merkle_hash_cs_independent_of_child_witness{false};
    /**
     * Deliberately false until the Decoder phase consumes every hash-task
     * source address and every predecessor/root digest through an executable
     * same-proof carry relation. Static hash equations alone do not prove
     * Merkle path ordering.
     */
    bool merkle_hash_row_semantic_carry_complete{false};
    alg_hash::Digest merkle_fold_program_root{};
    uint32_t merkle_fold_program_constraints{0};
    bool merkle_fold_constraints_canonical_bytecode{false};
    bool merkle_fold_program_root_recomputed{false};
    uint32_t merkle_fold_statement_manifest_r0_columns{0};
    uint32_t merkle_fold_proof_tape_cells{0};
    bool merkle_fold_proof_tape_cells_ordinary{false};
    bool merkle_fold_proof_tape_fixed_offsets{false};
    bool merkle_fold_equations_bound{false};
    bool merkle_fold_r0_statement_manifest_only{false};
    bool merkle_fold_cs_independent_of_child_witness{false};
    /** Open until beta/x/openings/final-value are carried from their owners. */
    bool merkle_fold_transcript_and_opening_carry_complete{false};
    alg_hash::Digest decoder_program_root{};
    uint32_t decoder_program_constraints{0};
    bool decoder_constraints_canonical_bytecode{false};
    bool decoder_program_root_recomputed{false};
    uint32_t decoder_statement_manifest_r0_columns{0};
    uint32_t decoder_proof_tape_cells{0};
    bool decoder_proof_tape_cells_ordinary{false};
    bool decoder_proof_tape_fixed_offsets{false};
    /**
     * Four Horner auxiliaries per source/consumer tuple and LogUp lane keep
     * the challenge-independent Decoder relation at degree two.  Expanding
     * gamma^4 inline would be degree six (seven after phase gating) and exceed
     * the production LDE cap.
     */
    bool decoder_degree_reduced_horner_chain{false};
    bool decoder_r0_statement_manifest_only{false};
    bool decoder_cs_independent_of_child_witness{false};
    bool decoder_challenge_columns_post_commit{false};
    bool decoder_program_challenge_independent{false};
    /** False until the parent transcript supplies gamma/alpha in this proof. */
    bool decoder_challenge_carry_complete{false};
    /** False until child receipt/root values are equality-carried here. */
    bool decoder_child_root_carry_complete{false};
    uint32_t phase_constraint_systems_canonical_bytecode{0};
    uint32_t phase_r0_tables_statement_manifest_only{0};
    bool trace_cap_fits{false};
    bool lde_cap_fits{false};
    /** False: phase R0 columns currently contain child-proof values. */
    bool cs_independent_of_child_witness{false};
    /** False: VerifyV1 currently receives and rebuilds from the child proof. */
    bool verifier_input_excludes_child_proof{false};
    bool quotient_cap_audit_complete{false};
    /** Open until proof-owned decoder/DEEP occurrences share a CTL bus. */
    bool direct_cross_phase_cell_carries_complete{false};
    bool recursive_authority_ready{false};
    bool valid_foundation{false};
    std::string note;
};

/**
 * Reconstruct the two production acceptance constraints as canonical,
 * consensus-serializable bytecode.  The table contains no witness-derived
 * constants and has a deterministic AlgHash root for a fixed LayoutV1.
 */
[[nodiscard]] cb::ProgramTable
BuildAcceptanceProgramTableV1(const LayoutV1& layout);

/** Canonical bytecode for active/one-hot/phase-boundary scheduling. */
[[nodiscard]] cb::ProgramTable
BuildSchedulerProgramTableV1(const LayoutV1& layout);

/**
 * Canonical bytecode for one row of the fixed-width Merkle Poseidon2 table:
 * all 472 decomposed permutation identities followed by the 12 input-pin and
 * four digest-output-pin equalities. The table contains no proof values.
 */
[[nodiscard]] cb::ProgramTable
BuildMerkleHashProgramTableV1(
    const mf::HashLayoutV1& layout =
        mf::CanonicalHashLayoutV1());

/**
 * Canonical bytecode for all thirteen Fp3 binary-fold, index, chain and
 * terminal equations. No beta, opening, index or final-value witness enters
 * the program bytes or R0.
 */
[[nodiscard]] cb::ProgramTable
BuildMerkleFoldProgramTableV1(
    const mf::FoldLayoutV1& layout =
        mf::CanonicalFoldLayoutV1());

/**
 * Canonical challenge-independent bytecode for the dual-Fp3 Decoder LogUp
 * relation.  The table extends the 24-column Decoder layout with sixteen
 * ordinary Horner auxiliaries and reads (gamma_0, gamma_1, alpha_0, alpha_1)
 * exclusively through the verifier-owned post-commit Challenge class.
 */
[[nodiscard]] cb::ProgramTable
BuildDecoderProgramTableV1(
    const dj::LayoutV1& layout =
        dj::CanonicalLayoutV1());

/**
 * Append the production acceptance-output constraints through the canonical
 * bytecode interpreter adapter.  No native constraint callback is a source of
 * truth on this path.
 */
[[nodiscard]] bool AppendAcceptanceOutputConstraintsV1(
    const LayoutV1& layout,
    aq::AirConstraintSystem<gf::Fp3>& cs,
    alg_hash::Digest* program_root = nullptr,
    std::string* why = nullptr);

/**
 * Rebuild the ParentJoin R0 commitment after removing the twelve
 * proof-derived transcript cells (eight absorb lanes and four digest
 * claims). The remaining table is immutable schedule/address metadata plus
 * verifier-selected public statement values.
 */
[[nodiscard]] uint256
ComputeParentJoinStatementManifestR0RootV1(
    const pj::ProductV1& parent_join,
    uint32_t* ordered_columns = nullptr,
    std::string* why = nullptr);

/**
 * Vertically concatenate parent-join, Merkle hash, fold, DEEP/VM and decoder
 * into one Split-RAP relation. Phase-private columns reuse max(width);
 * verifier-owned phase pins are separate R0 columns constrained equal under
 * immutable one-hot row tags.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range = {
        0, 0, kQ96QueriesV1});

[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

struct ProveResultV1 {
    aq::AirQuotientSplitRapRowsProof proof{};
    uint256 preprocessed_row_group_root{};
    uint64_t proof_wire_bytes{0};
    uint64_t prove_micros{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ProveResultV1 ProveV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const uint256& public_fs_seed);

struct VerifyResultV1 {
    uint64_t verify_micros{0};
    bool accepted{false};
    bool direct_cross_phase_cell_carries_complete{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] VerifyResultV1 VerifyV1(
    const rv::InputV1& input,
    const rv::QueryRangeV1& range,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed);

} // namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air

#endif
