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
inline constexpr uint32_t kPhasePrecommitRootWordsV1 = 8;
inline constexpr uint32_t kDecoderHornerStagesV1 = 4;
inline constexpr uint32_t kDecoderHornerAuxColumnsV1 =
    dj::kDecoderJoinBusLanesV1 * 2 *
    kDecoderHornerStagesV1;
inline constexpr uint32_t kDeepVmNativeConstraintsV1 = 284;
inline constexpr uint32_t kDeepVmRegisterBusLanesV1 = 2;
inline constexpr uint32_t kDeepVmRegisterBusSidesV1 = 3;
inline constexpr uint32_t kDeepVmRegisterHornerStagesV1 = 4;
inline constexpr uint32_t kDeepVmChallengeColumnsV1 = 4;
inline constexpr uint32_t kDeepVmSsaScheduleColumnsV1 = 6;
inline constexpr uint32_t kDeepVmRegisterAuxColumnsV1 =
    kDeepVmRegisterBusLanesV1 *
    (kDeepVmRegisterBusSidesV1 *
         (kDeepVmRegisterHornerStagesV1 + 1) +
     1);
inline constexpr uint32_t kDeepVmExtensionColumnsV1 =
    kDeepVmSsaScheduleColumnsV1 +
    kDeepVmRegisterAuxColumnsV1;
inline constexpr uint32_t kDeepVmCanonicalConstraintsV1 =
    kDeepVmNativeConstraintsV1 + 1 +
    kDeepVmRegisterBusLanesV1 *
        (kDeepVmRegisterBusSidesV1 *
             (kDeepVmRegisterHornerStagesV1 + 1) +
         3);
inline constexpr uint32_t kDeepVmStatementScheduleColumnsV1 =
    20 + kDeepVmSsaScheduleColumnsV1;
inline constexpr uint32_t
    kParentJoinStatementScheduleColumnsV1 =
        3 +
        pj::kPublicAbsorbSlotsV1 * 4 +
        pj::kPublicFieldSlotsV1 * 7 +
        pj::kCandidateDigestLimbsV1 * 3 +
        2 + 2;
static_assert(
    kParentJoinStatementScheduleColumnsV1 ==
    72);

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
inline constexpr uint32_t kPhasePrecommitRootColumnsV1 =
    kPhasesV1 * kPhasePrecommitRootWordsV1;
inline constexpr uint32_t kDecoderRootSelectorColumnsV1 =
    3 * kPhasePrecommitRootWordsV1;

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
    /**
     * Five phase-precommit roots, each encoded as eight canonical u32
     * words.  These are complete R0 columns, so every normalized FRI query
     * authenticates the exact same roots before any dependent challenge is
     * consumed.
     */
    uint32_t phase_precommit_root_base{0};
    /**
     * One immutable selector per Decoder child-root word.  A selector is one
     * only on the exact Decoder row which consumes that word; its equality
     * constraint directly aliases root_value to PhasePrecommitRoot(...).
     */
    uint32_t decoder_root_selector_base{0};
    uint32_t decoder_root_selector_columns{0};
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
    [[nodiscard]] uint32_t PhasePrecommitRoot(
        PhaseV1 phase, uint32_t word) const
    {
        return phase_precommit_root_base +
            static_cast<uint32_t>(phase) *
                kPhasePrecommitRootWordsV1 +
            word;
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
    alg_hash::Digest deep_vm_program_root{};
    uint32_t deep_vm_program_constraints{0};
    bool deep_vm_constraints_canonical_bytecode{false};
    bool deep_vm_program_root_recomputed{false};
    uint32_t deep_vm_statement_manifest_r0_columns{0};
    uint32_t deep_vm_proof_tape_cells{0};
    bool deep_vm_proof_tape_cells_ordinary{false};
    bool deep_vm_proof_tape_fixed_offsets{false};
    bool deep_vm_schedule_independently_regenerated{false};
    bool deep_vm_r0_statement_manifest_only{false};
    bool deep_vm_cs_independent_of_child_witness{false};
    bool deep_vm_program_and_range_bound{false};
    bool deep_vm_program_constants_owned{false};
    bool deep_vm_internal_ssa_copy_provenance{false};
    uint256 deep_vm_register_precommit_root{};
    /** Open until the parent transcript supplies both dual-Fp3 lanes. */
    bool deep_vm_register_challenge_carry_complete{false};
    /** Open until transcript, opening and source-address owners are carried. */
    bool deep_vm_value_and_source_carry_complete{false};
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
    bool phase_precommit_roots_r0_exported{false};
    bool phase_precommit_roots_canonical_u32{false};
    bool decoder_root_rows_directly_aliased{false};
    uint32_t decoder_root_words_directly_aliased{0};
    alg_hash::Digest decoder_root_alias_program_root{};
    bool decoder_root_alias_constraints_canonical_bytecode{false};
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
 * One trace-group opening copied from the normalized Split-RAP proof.
 *
 * These are coefficient-LDE rows, not host copies of H-domain witness rows.
 * `VerifyAuthenticatedTraceOpeningsV1` recomputes every row leaf and Merkle
 * path against `root`; consumers must use only cells in these authenticated
 * rows.  Keeping the query occurrence ordinal prevents a with-replacement
 * schedule from being silently deduplicated or reordered.
 */
struct AuthenticatedTraceRowV1 {
    uint32_t query_ordinal{0};
    uint32_t query_index{0};
    std::vector<gf::Fp3> values;
    std::vector<Fri3AlgDigest> siblings;
    uint32_t next_query_index{0};
    std::vector<gf::Fp3> next_values;
    std::vector<Fri3AlgDigest> next_siblings;
};

struct AuthenticatedTraceGroupV1 {
    Fri3AlgMultiRowGroupRole role{
        Fri3AlgMultiRowGroupRole::MainTrace};
    uint32_t first_column{0};
    uint32_t column_count{0};
    uint32_t n_leaves{0};
    uint256 root{};
    std::vector<AuthenticatedTraceRowV1> rows;
};

struct AuthenticatedTraceOpeningsV1 {
    uint16_t version{kVersionV1};
    uint32_t trace_rows{0};
    std::vector<uint32_t> base_column_indices;
    std::array<AuthenticatedTraceGroupV1, 2> groups{};
    uint256 opening_receipt_root{};
    bool every_consumed_cell_merkle_authenticated{false};
    bool exact_query_occurrence_order{false};
    bool canonical_fp3_and_digest_cells{false};
    /**
     * False here: only the complete Split-RAP/FRI verifier proves that these
     * ordered indices are the Fiat-Shamir-selected query schedule.
     */
    bool query_schedule_fiat_shamir_verified{false};
    bool valid{false};
    std::string note;
};

struct NormalizedOpeningReceiptV1;

[[nodiscard]] uint256
ComputeAuthenticatedTraceOpeningReceiptRootV1(
    const AuthenticatedTraceOpeningsV1& receipt);

/**
 * Extract and independently authenticate the R0 and Rdep query rows of a
 * normalized proof.  The quotient group is deliberately excluded: it is
 * checked by the full Split-RAP verifier and is not a source of phase input
 * cells.
 */
[[nodiscard]] AuthenticatedTraceOpeningsV1
BuildAuthenticatedTraceOpeningsV1(
    const aq::AirQuotientSplitRapRowsProof& proof);

/**
 * Verify an opening receipt against the exact normalized proof that owns it.
 * This performs no host callback and receives no backend child proof.
 */
[[nodiscard]] bool VerifyAuthenticatedTraceOpeningsV1(
    const AuthenticatedTraceOpeningsV1& receipt,
    const aq::AirQuotientSplitRapRowsProof& proof,
    std::string* why = nullptr);

/**
 * Require every phase-precommit u32 word at both the current and next
 * normalized R0 openings.  The opening paths themselves must first be
 * checked with VerifyAuthenticatedTraceOpeningsV1.
 */
[[nodiscard]] bool VerifyPhasePrecommitRootOpeningsV1(
    const NormalizedOpeningReceiptV1& receipt,
    std::string* why = nullptr);

/**
 * Canonical Decoder carry challenges.  Arbitrary uint256 roots are absorbed
 * as eight u32 limbs, never four reduced u64 field elements, closing the
 * Goldilocks x <-> x+p transcript alias in the older Decoder helper.
 */
[[nodiscard]] std::array<gf::Fp3, kDecoderChallengeColumnsV1>
DeriveDecoderCarryChallengesV1(
    const uint256& tuple_precommit_root);

/**
 * Raw-child-proof-free descriptor for the normalized parent verifier.
 *
 * This receipt binds the exact authenticated trace openings, all five
 * canonical phase programs, phase-local precommit-root metadata, the child
 * statement and child ProgramTable root/range. The precommit roots remain
 * binding-only metadata until proof-owned root cells are exported and
 * authenticated by `trace_openings`; challenge-replay flags therefore stay
 * false. It is intentionally not a recursive authority receipt yet: the
 * remaining phase verifier chips must consume the authenticated cells and
 * complete child receipts in the same parent proof.
 */
struct NormalizedOpeningReceiptV1 {
    uint16_t version{kVersionV1};
    rv::QueryRangeV1 range{};
    uint256 child_statement_root{};
    alg_hash::Digest child_program_root{};
    std::array<alg_hash::Digest, kPhasesV1>
        phase_program_root{};
    std::array<uint256, kPhasesV1>
        phase_precommit_root{};
    std::array<PhaseShapeV1, kPhasesV1> phases{};
    AuthenticatedTraceOpeningsV1 trace_openings{};
    uint32_t phase_precommit_root_column_base{0};
    uint32_t phase_precommit_root_words{
        kPhasePrecommitRootWordsV1};
    uint256 receipt_root{};
    bool canonical_programs_bound{false};
    bool deep_vm_challenge_replayed{false};
    bool decoder_challenge_replayed{false};
    bool verifier_input_excludes_child_proof{false};
    bool every_consumed_cell_opening_authenticated{false};
    bool phase_precommit_roots_opening_authenticated{false};
    /** False until all phase verifier chips consume the authenticated rows. */
    bool complete_phase_verifier_consumption{false};
    /** False until complete recursively verified child receipts are joined. */
    bool complete_child_receipt_consumption{false};
    bool valid_foundation{false};
    std::string note;
};

[[nodiscard]] uint256 ComputeNormalizedOpeningReceiptRootV1(
    const NormalizedOpeningReceiptV1& receipt);

[[nodiscard]] NormalizedOpeningReceiptV1
BuildNormalizedOpeningReceiptV1(
    const ProductV1& product,
    const alg_hash::Digest& child_program_root,
    const uint256& child_statement_root,
    const aq::AirQuotientSplitRapRowsProof& proof);

struct NormalizedOpeningVerifyResultV1 {
    std::array<gf::Fp3, kDeepVmChallengeColumnsV1>
        deep_vm_challenge{};
    std::array<gf::Fp3, kDecoderChallengeColumnsV1>
        decoder_challenge{};
    bool opening_paths_verified{false};
    bool phase_precommit_roots_opening_authenticated{false};
    bool canonical_programs_verified{false};
    bool challenge_replay_verified{false};
    bool raw_child_proof_excluded{false};
    bool full_split_rap_transcript_verified{false};
    bool complete_phase_verifier_consumption{false};
    bool complete_child_receipt_consumption{false};
    bool accepted_foundation{false};
    std::string note;
};

[[nodiscard]] NormalizedOpeningVerifyResultV1
VerifyNormalizedOpeningReceiptV1(
    const NormalizedOpeningReceiptV1& receipt,
    const aq::AirQuotientSplitRapRowsProof& proof);

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
 * Proof-value-free structural projection of the canonical child ABI.
 *
 * Roots, openings, query indices, fold challenges and terminal values are
 * deliberately absent.  Only dimensions that determine the verifier's
 * Merkle/fold row schedule survive this projection.
 */
struct MerkleFoldPublicShapeV1 {
    uint16_t version{kVersionV1};
    uint32_t trace_rows{0};
    uint32_t n_coeffs{0};
    uint32_t blowup{0};
    uint32_t n_lde{0};
    uint32_t row_depth{0};
    std::array<uint32_t, 3> group_columns{};
    uint32_t fold_count{0};
    uint32_t proof_query_count{0};
    bool canonical_projection{false};
    bool proof_values_excluded{false};
    bool valid{false};
    std::string note;

    bool operator==(const MerkleFoldPublicShapeV1&) const = default;
};

[[nodiscard]] MerkleFoldPublicShapeV1
BuildMerkleFoldPublicShapeV1(
    const abi::DecodedV1& decoded);

/**
 * Canonical Merkle-hash and binary-fold verifier plan derived exclusively
 * from the public structural projection and the verifier-selected range.
 * Neither child roots nor any proof-owned opening cell can affect a program,
 * row count or constraint system.
 */
struct MerkleFoldPublicPlanV1 {
    uint16_t version{kVersionV1};
    MerkleFoldPublicShapeV1 shape{};
    rv::QueryRangeV1 range{};
    mf::HashLayoutV1 hash_layout{};
    mf::FoldLayoutV1 fold_layout{};
    cb::ProgramTable hash_program{};
    cb::ProgramTable fold_program{};
    alg_hash::Digest hash_program_root{};
    alg_hash::Digest fold_program_root{};
    aq::AirConstraintSystem<gf::Fp3> hash_cs{};
    aq::AirConstraintSystem<gf::Fp3> fold_cs{};
    uint32_t hash_real_rows{0};
    uint32_t hash_trace_rows{0};
    uint32_t fold_real_rows{0};
    uint32_t fold_trace_rows{0};
    bool row_schedule_canonical{false};
    bool constraint_systems_canonical{false};
    bool proof_independent{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] MerkleFoldPublicPlanV1
BuildMerkleFoldPublicPlanV1(
    const MerkleFoldPublicShapeV1& shape,
    const rv::QueryRangeV1& range);

struct MerkleFoldCanonicalPhasesV1 {
    cb::ProgramTable hash_program{};
    cb::ProgramTable fold_program{};
    aq::AirConstraintSystem<gf::Fp3> hash_cs{};
    aq::AirConstraintSystem<gf::Fp3> fold_cs{};
    std::vector<std::vector<gf::Fp3>> hash_columns;
    std::vector<std::vector<gf::Fp3>> fold_columns;
    bool public_plan_recomputed{false};
    bool proof_tape_ordinary{false};
    bool valid{false};
    std::string note;
};

/**
 * Copy only ordinary child-proof witness cells under a canonical public plan.
 * Any substituted shape, row schedule, ProgramTable, root or constraint
 * system is rejected before witness evaluation.
 */
[[nodiscard]] MerkleFoldCanonicalPhasesV1
MaterializeMerkleFoldCanonicalPhasesV1(
    const MerkleFoldPublicPlanV1& plan,
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard);

/**
 * Canonical bytecode for all 284 Deep/VM/quotient-tape equations plus
 * verifier-owned constant equality and a dual-Fp3 register LogUp.  The LogUp
 * binds every Add/Sub/Mul operand to the referenced prior SSA result under
 * (query, program, register, value), with exact use multiplicities derived
 * from the canonical child ProgramTable. Current/Next source values remain
 * ordinary tape for the later ABI carry.
 */
[[nodiscard]] cb::ProgramTable
BuildDeepVmProgramTableV1(
    const dvm::LayoutV1& layout =
        dvm::CanonicalLayoutV1());

/**
 * Verifier-owned DeepVM plan.  Every field is derived exclusively from the
 * canonical child ProgramTable, its registry-selected root and QueryRange.
 * In particular no child proof, transcript value, trace commitment or
 * proof-derived R0 root is an input to this construction.
 */
struct DeepVmPublicPlanV1 {
    uint16_t version{kVersionV1};
    rv::QueryRangeV1 range{};
    dvm::LayoutV1 layout{};
    cb::ProgramTable child_program{};
    alg_hash::Digest child_program_root{};
    cb::ProgramTable program{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<uint32_t> statement_manifest_columns;
    std::vector<gf::Fp3> challenge;
    uint256 statement_schedule_root{};
    uint32_t real_rows{0};
    uint32_t trace_rows{0};
    bool child_program_root_recomputed{false};
    bool statement_schedule_canonical{false};
    bool constraint_system_canonical{false};
    bool proof_independent{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] DeepVmPublicPlanV1
BuildDeepVmPublicPlanV1(
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range);

/**
 * Build the canonical DeepVM phase in isolation for recursive composition
 * and adversarial proof audits. The four verifier-owned Challenge cells
 * (gamma_0, gamma_1, alpha_0, alpha_1) are domain-separated from the child
 * DeepVM operand/opcode precommit root, canonical child-program root and
 * exact query range. They are consumed through Challenge opcodes and never
 * committed as ordinary/R0 witness data in this normalized parent.
 */
struct DeepVmCanonicalPhaseV1 {
    cb::ProgramTable program{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> statement_manifest_columns;
    std::vector<gf::Fp3> challenge;
    bool program_and_range_bound{false};
    bool constant_schedule_owned{false};
    bool register_logup_complete{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] DeepVmCanonicalPhaseV1
BuildDeepVmCanonicalPhaseV1(
    const dvm::ProductV1& deep,
    const cb::ProgramTable& child_program,
    const alg_hash::Digest& expected_program_root,
    const rv::QueryRangeV1& range);

/**
 * Materialize only the ordinary proof-derived witness columns under an
 * already-built public plan.  The function rebuilds the plan canonically and
 * rejects any ProgramTable, schedule, root, range or shape substitution
 * before copying proof cells.
 */
[[nodiscard]] DeepVmCanonicalPhaseV1
MaterializeDeepVmCanonicalPhaseV1(
    const DeepVmPublicPlanV1& plan,
    const dvm::ProductV1& deep);

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
 * Canonical 24-equation same-parent bridge from the Decoder root_value tape
 * to the ParentJoin, MerkleHash and MerkleFold precommit-root R0 exports.
 */
[[nodiscard]] cb::ProgramTable
BuildDecoderRootAliasProgramTableV1(
    const LayoutV1& layout,
    const dj::LayoutV1& decoder =
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
