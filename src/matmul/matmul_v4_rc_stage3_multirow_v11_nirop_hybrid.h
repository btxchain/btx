// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NIROP_HYBRID_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NIROP_HYBRID_H

#include <matmul/matmul_v4_rc_stage3_multirow_p2_transcript.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid {

namespace gf = gkr_field;
namespace p2 = stage3_multirow_p2_transcript;

inline constexpr uint16_t kManifestVersionV1 = 1;
inline constexpr uint32_t kTranscriptDomainCountV1 = 14;

/**
 * The fourteen native V11 transcript hash roles, in transcript order.
 * Several roles occur more than once, but every occurrence has exactly one
 * of these domain prefixes.
 */
enum class TranscriptRoleV1 : uint8_t {
    ShapeCommit = 1,
    AirLambda = 2,
    FriSeed = 3,
    OodZ1Candidate = 4,
    OodZ2Candidate = 5,
    OodEvaluationCommit = 6,
    BatchSeed = 7,
    BatchCoefficient = 8,
    DeepWeight = 9,
    FoldState = 10,
    FoldBeta = 11,
    QuerySeed = 12,
    QueryCandidate = 13,
    Padding = 14,
};

struct TranscriptDomainV1 {
    TranscriptRoleV1 role{};
    uint64_t domain{0};
    const char* label{nullptr};
};

/**
 * One exact V11 hash-DAG event re-expressed as the low-delta stateless
 * SAFECore call C(IO=(absorb_lanes,squeeze_lanes), D=typed role, M).
 */
struct SafeIoEventV1 {
    TranscriptRoleV1 role{};
    uint32_t ordinal{0};
    uint32_t absorb_lanes{0};
    uint32_t squeeze_lanes{0};
};

/** Exact, reviewable list used by the independent replay audit. */
[[nodiscard]] const std::array<
    TranscriptDomainV1, kTranscriptDomainCountV1>&
CanonicalTranscriptDomainsV1();

/**
 * A concrete identical-input witness between two nominal oracle roles.
 *
 * `LeafHashRow` hashes [three coordinates per row cell, row_index] with the
 * generic zero-capacity SpongeHashFp mode. A V11 coefficient, fold-beta or
 * query-candidate draw hashes
 * [domain_lo32, domain_hi32, digest[0..3], ordinal]. For a two-cell row those
 * are the same seven lanes, not merely equal digests.
 */
struct CrossRoleIdenticalInputV1 {
    TranscriptRoleV1 transcript_role{
        TranscriptRoleV1::BatchCoefficient};
    uint64_t transcript_domain{0};
    std::array<gf::Fp3, 2> row_cells{};
    uint32_t row_index{0};
    std::vector<gf::Fp> transcript_sponge_input;
    std::vector<gf::Fp> row_leaf_sponge_input;
    Fri3AlgDigest transcript_digest{};
    Fri3AlgDigest row_leaf_digest{};
    bool lane_vectors_identical{false};
    bool padded_inputs_identical{false};
    bool digests_identical_without_collision{false};
};

struct TranscriptDagAuditV1 {
    uint16_t manifest_version{kManifestVersionV1};
    uint32_t protocol_version{0};
    uint64_t protocol_domain{0};
    uint32_t transcript_domain_count{0};
    uint32_t expected_hash_events{0};
    uint32_t independently_replayed_hash_events{0};
    uint32_t queries{0};
    uint32_t query_candidates{0};
    std::vector<SafeIoEventV1> proposed_safe_io_events;

    bool statement_shape_precedes_shape_commit{false};
    bool statement_prefix_precedes_r0_rdep_roots_in_air_lambda{false};
    bool statement_prefix_precedes_all_roots_in_fri_seed{false};
    bool air_lambda_before_quotient_root{false};
    bool all_roots_before_ood_draws{false};
    bool ood_claims_before_batch_coefficients{false};
    bool each_fold_root_before_its_beta{false};
    bool terminal_before_query_seed{false};
    bool query_seed_before_all_q192_candidates{false};
    bool q192_k2_schedule_injective{false};
    bool q192_with_replacement{false};

    bool fourteen_domains_pairwise_distinct{false};
    bool u64_domains_split_into_two_canonical_u32_lanes{false};
    bool independent_replay_matches_native_receipt{false};
    bool native_receipt_verifies{false};

    bool rbr_parameters_match_v11{false};
    bool q192_rbr_ledger_machine_checked{false};
    double rbr_query_proximity_bits{0.0};
    double rbr_poseidon_collision_bits{0.0};
    double rbr_composed_single_lane_bits{0.0};

    bool merkle_node_capacity_domain_separated{false};
    bool fold_leaf_fixed_width_rate_tagged{false};
    bool fold_leaf_capacity_domain_separated{false};
    bool row_leaf_role_domain_separated{false};
    bool merkle_oracle_and_fs_sponge_inputs_disjoint{false};
    /** V11's SpongeHashFp adds blocks into the rate; it is not overwrite DS. */
    bool v11_uses_add_absorb_sponge{false};
    bool v11_uses_overwrite_mode_duplex{false};
    /** DSFS starts capacity from h(instance); V11 starts it at zero. */
    bool v11_uses_instance_derived_capacity_start{false};
    bool published_duplex_fs_premises_match{false};
    bool custom_add_absorb_hash_chain_hybrid_complete{false};
    CrossRoleIdenticalInputV1 row_leaf_vs_coefficient;
    CrossRoleIdenticalInputV1 row_leaf_vs_fold_beta;
    CrossRoleIdenticalInputV1 row_leaf_vs_query_candidate;

    /**
     * A first-collision hybrid may only be asserted after every role has
     * disjoint input encoding, so this remains false for V11.
     */
    bool poseidon_first_collision_hybrid_complete{false};
    bool nirop_bcs_composition_complete{false};
    bool production_authority_ready{false};
    std::vector<std::string> required_call_site_migrations;
    std::string required_protocol_change;
    std::string note;
};

/**
 * Independently replay the native V11 transcript and inspect the real
 * Merkle/fold encodings. No readiness constant is consumed or produced.
 */
[[nodiscard]] TranscriptDagAuditV1 AssessV1(
    const p2::StatementV1& statement);

// -------------------------------------------------------------------------
// Additive V12 hash-role encoding. This is the mandatory protocol-version
// fix identified by AssessV1; no V11 call site selects it yet.
// -------------------------------------------------------------------------

inline constexpr uint16_t kTypedHashVersionV1 = 1;
inline constexpr uint32_t kTypedHashProtocolVersionV12 = 12;
inline constexpr gf::Fp kTypedHashCapacityMagicV1 =
    0x4254585459504544ULL; // "BTXTYPED", canonical in Goldilocks.

enum class TypedHashRoleV1 : uint32_t {
    MerkleRowLeaf = 1,
    MerkleFoldLeaf = 2,
    MerkleInternalNode = 3,
    TranscriptShapeCommit = 4,
    TranscriptAirLambda = 5,
    TranscriptFriSeed = 6,
    TranscriptOodZ1 = 7,
    TranscriptOodZ2 = 8,
    TranscriptOodEvaluations = 9,
    TranscriptBatchSeed = 10,
    TranscriptBatchCoefficient = 11,
    TranscriptDeepWeight = 12,
    TranscriptFoldState = 13,
    TranscriptFoldBeta = 14,
    TranscriptQuerySeed = 15,
    TranscriptQueryCandidate = 16,
    TranscriptPadding = 17,
    ReceiptCommitment = 18,
    ProgramTableCommitment = 19,
    ApplicationStatementCommitment = 20,
};

struct TypedPermutationCallV1 {
    TypedHashRoleV1 role{};
    std::array<gf::Fp, alg_hash::kAlgHashT> input{};
    std::array<gf::Fp, alg_hash::kAlgHashT> output{};
};

struct TypedHashResultV1 {
    Fri3AlgDigest digest{};
    std::vector<TypedPermutationCallV1> calls;
    bool valid{false};
};

/** Variable-length typed sponge. Role lives in non-witness capacity lanes. */
[[nodiscard]] TypedHashResultV1 TypedSpongeHashFpV1(
    TypedHashRoleV1 role,
    const std::vector<gf::Fp>& lanes);

/** Typed, fixed-width encodings for the two Merkle primitives. */
[[nodiscard]] TypedHashResultV1 TypedRowLeafV1(
    const std::vector<gf::Fp3>& row, uint32_t index);
/**
 * Column-chunked implementation of the same row encoding. `columns_per_block`
 * affects memory traversal only; the absorbed lane sequence is identical.
 */
[[nodiscard]] TypedHashResultV1 TypedRowLeafStreamingV1(
    const std::vector<gf::Fp3>& row, uint32_t index,
    uint32_t columns_per_block);
[[nodiscard]] TypedHashResultV1 TypedFoldLeafV1(
    const gf::Fp3& value, uint32_t index);
[[nodiscard]] TypedHashResultV1 TypedMerkleNodeV1(
    const Fri3AlgDigest& left, const Fri3AlgDigest& right);

struct TypedHashSeparationAuditV1 {
    uint16_t typed_hash_version{kTypedHashVersionV1};
    uint32_t protocol_version{kTypedHashProtocolVersionV12};
    uint32_t role_count{0};
    bool capacity_magic_canonical{false};
    bool every_role_capacity_tuple_unique{false};
    bool rate_lanes_cannot_overwrite_capacity_domain{false};
    bool variable_length_padding_injective{false};
    bool host_poseidon_air_permutation_parity{false};
    uint32_t parity_calls_checked{0};
    bool initial_call_role_encodings_disjoint{false};
    bool fixed_leaf_node_vs_sponge_starts_disjoint{false};
    bool row_leaf_streaming_equivalent{false};
    bool active_v11_backend_migrated{false};
    bool recursive_replay_migrated{false};
    bool first_collision_hybrid_ready{false};
    bool production_authority_ready{false};
    std::string note;
};

/**
 * Exercise every typed role on adversarial rate lanes (including domain-like
 * prefixes) and compare every host permutation call with the Poseidon AIR
 * witness. Readiness remains false until V11 is version-bumped and migrated.
 */
[[nodiscard]] TypedHashSeparationAuditV1
AuditTypedHashSeparationV1();

// -------------------------------------------------------------------------
// Two honest production paths from the V11 audit.
// -------------------------------------------------------------------------

struct SharedPermutationBudgetV1 {
    uint64_t proof_sites{0};
    uint64_t fs_permutation_calls_per_site{0};
    uint64_t merkle_permutation_calls_per_site{0};
    uint64_t receipt_program_calls_per_site{0};
    uint64_t adversary_permutation_queries_per_site{0};
    /** Exact honest H(IO,D) calls from the protocol manifest. */
    uint64_t safe_tag_hash_queries{0};
    /**
     * Separately declared adversarial budgets. A 64-bit classical security
     * screen sets both to 64.0, i.e. permits up to 2^64 H and P queries.
     */
    double adversarial_h_query_budget_log2{0.0};
    double adversarial_permutation_query_budget_log2{0.0};
    bool exact_manifest_derived{false};
};

struct TypedAddAbsorbHybridAuditV1 {
    SharedPermutationBudgetV1 budget{};
    double goldilocks_bits{0.0};
    double shared_permutation_queries_log2{0.0};
    double generic_capacity_first_collision_bits{0.0};
    double poseidon_algebraic_floor_after_site_union_bits{0.0};
    double effective_first_collision_bits{0.0};
    bool all_shared_permutation_queries_summed_before_square{false};
    bool adaptive_multiblock_capacity_collisions_accounted{false};
    bool typed_initial_role_ivs_disjoint{false};
    bool ten_star_message_encoding_prefix_free{false};
    bool add_absorb_next_input_injective_given_prior_state{false};
    bool concrete_poseidon_ideal_permutation_assumption_disclosed{false};
    bool custom_reduction_formally_complete{false};
    bool exact_global_call_manifest_enforced{false};
    bool active_native_transcript_matches{false};
    bool recursive_air_transcript_matches{false};
    bool gpu_friendly_poseidon_preserved{false};
    bool numeric_v1_security_screen_met{false};
    bool production_theorem_complete{false};
    std::vector<std::string> assumptions;
    std::string note;
};

/**
 * Numeric first-collision screen for path A. Every use of the shared
 * permutation is summed before the birthday square; no role is treated as an
 * independent lane. This is not itself a proof of the custom reduction.
 */
[[nodiscard]] TypedAddAbsorbHybridAuditV1
AssessTypedAddAbsorbHybridV1(
    const SharedPermutationBudgetV1& budget);

struct OverwriteDuplexFsAuditV1 {
    uint32_t minimum_capacity_lanes{0};
    uint32_t persistent_duplex_state_lanes{0};
    uint32_t poseidon_air_columns_per_parameter_set{0};
    uint32_t minimum_independent_oracle_families{0};
    uint32_t additional_poseidon_parameter_sets_vs_v11{0};
    bool published_transform_is_overwrite_mode{false};
    bool published_start_capacity_is_instance_derived{false};
    bool published_bcs_keeps_merkle_compression_separate{false};
    bool current_v11_add_absorb_matches{false};
    bool current_v11_zero_capacity_start_matches{false};
    bool same_parameter_set_domain_tags_are_proven_independent{false};
    bool independent_start_fs_merkle_parameter_sets_executable{false};
    bool native_overwrite_transcript_executable{false};
    bool recursive_overwrite_transcript_executable{false};
    bool gpu_friendly_if_poseidon_parameter_sets_added{false};
    bool published_dsfs_premises_instantiated{false};
    bool production_theorem_complete{false};
    std::vector<std::string> assumptions;
    std::string note;
};

/** Fail-closed implementation delta for path B (ePrint 2025/536 DSFS). */
[[nodiscard]] OverwriteDuplexFsAuditV1
AssessOverwriteDuplexFsV1();

/**
 * Published SAFECore route (ePrint 2023/520, Theorem 2).
 *
 * SAFE API 2023/522 writes at most c/2 tag elements. For Goldilocks c=4,
 * the security report explains that profile only screens at |Fp|^(c/4),
 * about 64 bits. The improved SAFECore theorem initializes the entire
 * c-element inner part with H(IO,D), recovering |Fp|^(c/2).
 */
struct SafeCoreMigrationAuditV1 {
    uint32_t rate_lanes{0};
    uint32_t capacity_lanes{0};
    uint32_t width_lanes{0};
    uint32_t safe_api_spec_tag_lanes{0};
    uint32_t proved_safecore_tag_lanes{0};
    double safe_api_spec_query_ceiling_bits{0.0};
    double proved_safecore_query_ceiling_bits{0.0};
    uint32_t v11_transcript_hash_events{0};
    uint32_t proposed_safe_io_absorb_squeeze_events{0};
    uint64_t theorem_unique_h_queries{0};
    uint64_t honest_tag_hash_queries{0};
    double theorem_h_queries_log2{0.0};
    double theorem_unique_permutation_queries_log2{0.0};
    double theorem_indifferentiability_bits{0.0};
    double conditional_poseidon_algebraic_floor_bits{0.0};
    double conditional_effective_bits{0.0};

    bool theorem2_bound_computed{false};
    bool adversarial_classical_query_budgets_included{false};
    bool theorem2_numeric_v1_screen_met{false};
    bool safe_api_two_lane_profile_meets_v1_screen{false};
    bool current_v11_resets_state_per_hash_event{false};
    bool current_v11_is_one_continuous_safe_state{false};
    bool current_v11_capacity_is_full_h_io_domain_tag{false};
    bool current_v11_io_pattern_fixed_and_enforced{false};
    bool current_v11_padding_matches_safecore_pad{false};
    bool typed_v12_static_iv_is_full_h_io_domain_tag{false};

    bool proposed_stateless_safecore_per_hash_event{false};
    bool proposed_seed_feedback_is_ordinary_message_data{false};
    bool proposed_safecore_zero_padding_fixed_by_io{false};
    bool proposed_fs_is_one_continuous_absorb_squeeze_state{false};
    bool proposed_fs_has_fixed_io_pattern{false};
    bool proposed_native_seed_feedback_removed{false};
    bool proposed_merkle_instances_have_separate_tags{false};
    bool proposed_receipt_program_instances_have_separate_tags{false};
    bool proposed_uses_full_capacity_tag{false};
    bool proposed_tag_hash_to_fp4_is_canonical{false};
    bool proposed_tag_registry_root_pinned{false};
    bool exact_safe_io_pattern_manifest_enforced{false};
    bool native_safe_transcript_executable{false};
    bool recursive_safe_transcript_executable{false};
    bool gpu_friendly_poseidon_preserved{false};
    bool tag_hash_random_oracle_assumption_disclosed{false};
    bool poseidon_random_permutation_assumption_disclosed{false};
    bool concrete_tag_hash_reduction_complete{false};
    bool concrete_poseidon_reduction_complete{false};
    bool published_safecore_premises_instantiated{false};
    bool production_theorem_complete{false};
    std::vector<std::string> premise_mismatches;
    std::vector<std::string> required_protocol_changes;
    std::string note;
};

/**
 * Compare actual V11 semantics with SAFE/SAFECore and evaluate the exact
 * Theorem-2 advantage expression under the supplied global query budget.
 */
[[nodiscard]] SafeCoreMigrationAuditV1 AssessSafeCoreMigrationV1(
    const p2::StatementV1& statement,
    const SharedPermutationBudgetV1& budget);

// -------------------------------------------------------------------------
// V13 SAFE/Q192 concrete-composition reduction.
// -------------------------------------------------------------------------

/**
 * Evidence supplied by the executable V13 transcript, recursive parent and
 * global topology.  The mathematical reduction below deliberately accepts
 * these as premises so it can be unit-tested under premise removal; the
 * production ledger must populate them from independently recomputed
 * assessments, never from a readiness flag.
 */
struct SafeQ192ReductionPremisesV13 {
    bool exact_typed_io_domain_program{false};
    bool domain_registry_root_rebuilt_and_pinned{false};
    bool native_safe_q192_transcript_executable{false};
    bool native_safe_q192_verifier_replays_transcript{false};
    bool recursive_safe_event_parent_proved{false};
    bool every_recursive_message_cell_authenticated{false};
    bool every_recursive_output_cell_consumed{false};
    bool canonical_query_seed_is_sole_query_source{false};
    bool exact_global_h_p_manifest_enforced{false};
    bool all_shared_poseidon_calls_counted_before_square{false};
    bool typed_commitment_encodings_injective{false};
    bool native_recursive_poseidon_parity{false};
    bool adaptive_statement_and_oracle_queries_accounted{false};

    /**
     * Standard computational-instantiation assumptions.  These are policy
     * inputs, not facts inferred from domain strings:
     *
     *  - SHA256d instantiates SAFECore's vector-valued H(IO,D) random oracle;
     *  - the frozen Poseidon2 permutation instantiates SAFECore's public
     *    ideal permutation and the commitment permutation.
     */
    bool sha256d_random_oracle_assumption_accepted{false};
    bool poseidon2_ideal_permutation_assumption_accepted{false};
};

/**
 * One global query inventory.  Honest counts are exact manifest counts;
 * adversarial budgets are added before applying either birthday bound.
 */
struct SafeQ192QueryBudgetV13 {
    uint64_t honest_h_queries{0};
    uint64_t honest_poseidon_queries{0};
    double adversarial_h_queries_log2{0.0};
    double adversarial_poseidon_queries_log2{0.0};
    bool exact_manifest_derived{false};
};

// -------------------------------------------------------------------------
// Exact per-accepted-proof V13 H/P/query inventory.
// -------------------------------------------------------------------------

/**
 * One H(IO,D,counter) call made by the V13 SAFE tag rejection sampler.
 *
 * `canonical_io_words`, `typed_domain` and `rejection_counter` uniquely
 * determine the SHA256d counter-XOF preimage together with the frozen V12
 * SAFE parameter tuple.  Every rejection attempt is retained as a distinct
 * occurrence.  In particular, two byte-identical calls at different
 * verifier sites are not deduplicated.
 */
struct V13HOracleCallV1 {
    uint64_t occurrence{0};
    uint32_t safe_event{0};
    alg_hash_typed::RoleV12 role{
        alg_hash_typed::RoleV12::TranscriptBatchCoefficient};
    std::vector<uint32_t> canonical_io_words;
    std::vector<uint8_t> typed_domain;
    uint64_t rejection_counter{0};
    bool accepted{false};

    friend bool operator==(
        const V13HOracleCallV1&,
        const V13HOracleCallV1&) = default;
};

enum class V13POracleFamilyV1 : uint8_t {
    SafeCore = 1,
    ShapeCommit = 2,
    OodEvaluationCommit = 3,
    RowLeaf = 4,
    RowMerklePath = 5,
    FoldLeaf = 6,
    FoldMerklePath = 7,
    TerminalLeaf = 8,
    TerminalNode = 9,
};

/**
 * One concrete call to the single shared frozen Poseidon2 permutation.
 * `input` and `output` are canonical full-width states.  The occurrence
 * number is part of the manifest identity; equal states at distinct call
 * sites remain two queries and are charged twice before any birthday square.
 */
struct V13POracleCallV1 {
    uint64_t occurrence{0};
    V13POracleFamilyV1 family{V13POracleFamilyV1::SafeCore};
    uint32_t protocol_event{0};
    uint32_t local_call{0};
    alg_hash::State input{};
    alg_hash::State output{};

    friend bool operator==(
        const V13POracleCallV1&,
        const V13POracleCallV1&) = default;
};

/**
 * The verifier-visible query draw schedule.  Full SAFE outputs are retained,
 * not only the modulo-reduced index, so recursive replay cannot substitute an
 * arbitrary index with the same residue.
 */
struct V13CanonicalQueryEventV1 {
    uint32_t occurrence{0};
    Fri3AlgSafeV13Consumer consumer{
        Fri3AlgSafeV13Consumer::FriLambda};
    uint32_t family_ordinal{0};
    alg_hash_typed::RoleV12 role{
        alg_hash_typed::RoleV12::TranscriptBatchCoefficient};
    alg_hash::Digest safe_digest{};
    Fp3 consumed_fp3{};
    uint32_t consumed_index{0};
    bool acceptable{false};
    bool selected{false};

    friend bool operator==(
        const V13CanonicalQueryEventV1& left,
        const V13CanonicalQueryEventV1& right)
    {
        return left.occurrence == right.occurrence &&
            left.consumer == right.consumer &&
            left.family_ordinal == right.family_ordinal &&
            left.role == right.role &&
            left.safe_digest == right.safe_digest &&
            gf::Eq(left.consumed_fp3, right.consumed_fp3) &&
            left.consumed_index == right.consumed_index &&
            left.acceptable == right.acceptable &&
            left.selected == right.selected;
    }
};

/**
 * Explicit cells that a recursive verifier must export.  This type is
 * intentionally data-only: equality with the native manifest is a complete
 * parity check, but it is not evidence that a recursive AIR authenticated the
 * cells.  The latter remains a separate fail-closed production premise.
 */
struct V13RecursiveOracleParityInputsV1 {
    std::vector<V13HOracleCallV1> h_calls;
    std::vector<V13POracleCallV1> p_calls;
    std::vector<V13CanonicalQueryEventV1> query_events;
};

struct V13PerProofOracleInventoryV1 {
    uint32_t protocol_version{0};
    uint32_t width{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t folds{0};
    uint32_t queries{0};
    std::vector<V13HOracleCallV1> h_calls;
    std::vector<V13POracleCallV1> p_calls;
    std::vector<V13CanonicalQueryEventV1> query_events;
    uint64_t rejected_h_candidates{0};
    uint64_t accepted_h_candidates{0};
    uint64_t safe_p_calls{0};
    uint64_t commitment_p_calls{0};
    uint64_t merkle_p_calls{0};
    bool native_proof_accepted{false};
    bool exact_event_order{false};
    bool every_h_rejection_attempt_counted{false};
    bool every_shared_p_occurrence_counted{false};
    bool ordered_h_domains_bound{false};
    bool p_states_canonical_and_executable{false};
    bool canonical_query_seed_is_sole_query_source{false};
    bool native_recursive_inputs_equal{false};
    bool recursive_air_authenticates_parity_inputs{false};
    bool exact_per_proof_inventory{false};
    bool exact_global_topology_inventory{false};
    bool production_nirop_complete{false};
    std::vector<std::string> residual_premises;
    std::string note;
};

/**
 * Re-run the unmodified V13 verifier/replay and enumerate every SAFE H call,
 * every shared-Poseidon call made by SAFE, shape/OOD commitments and all
 * Merkle verification work, plus the exact query-event order.
 */
[[nodiscard]] bool BuildV13PerProofOracleInventoryV1(
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    V13PerProofOracleInventoryV1& out,
    std::string* why = nullptr);

/**
 * Rebuild the native inventory and equality-check the explicit recursive
 * cells.  Omission, duplication, reorder, cross-proof transplant and
 * non-canonical x+p lanes all fail.  This closes per-proof parity only;
 * recursive AIR authentication and the global 14-role topology remain false.
 */
[[nodiscard]] bool ValidateV13NativeRecursiveOracleParityV1(
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const V13RecursiveOracleParityInputsV1& recursive,
    V13PerProofOracleInventoryV1& out,
    std::string* why = nullptr);

/**
 * Machine-checked computational reduction for the selected single-lane V13
 * path.
 *
 * In the (H,P) model it applies SAFECore Theorem 2 exactly:
 *
 *   [3*C(QH,2)+2*C(QP,2)+4*QH*QP]/p^c
 *       + 3*C(QP,2)/p^b.
 *
 * The commitment first-collision hybrid uses one shared P-query inventory
 * (FS, Merkle, receipt, ProgramTable and adversarial direct calls) and the
 * conservative bad-event bound 2*T*(T+2R)/p^c.  No domain is treated as an
 * independent oracle.  The real-world bound is the union of those two ideal
 * model terms plus the explicitly supplied concrete H/P security floors.
 */
struct SafeQ192ReductionAssessmentV13 {
    uint32_t protocol_version{0};
    uint32_t queries{0};
    uint32_t ood_candidates{0};
    uint32_t rate_lanes{0};
    uint32_t capacity_lanes{0};
    uint32_t width_lanes{0};
    uint32_t typed_role_count{0};
    SafeQ192QueryBudgetV13 budget{};
    SafeQ192ReductionPremisesV13 premises{};

    double total_h_queries_log2{0.0};
    double total_poseidon_queries_log2{0.0};
    double safecore_indifferentiability_bits{0.0};
    double commitment_first_collision_bits{0.0};
    double sha256d_floor_bits{0.0};
    double poseidon2_floor_bits{0.0};
    double composed_computational_bits{0.0};

    bool canonical_v13_parameters{false};
    bool full_capacity_joint_rejection_tag_executable{false};
    bool safecore_theorem2_bound_computed{false};
    bool shared_permutation_first_collision_bound_computed{false};
    bool no_independent_domain_lane_claim{false};
    bool adversarial_classical_budgets_included{false};
    bool concrete_assumptions_explicit{false};
    bool numeric_v1_screen_met{false};
    bool oracle_separation_reduction_complete{false};
    bool commitment_binding_reduction_complete{false};
    bool production_composition_complete{false};
    std::vector<std::string> missing_premises;
    std::string note;
};

[[nodiscard]] SafeQ192ReductionAssessmentV13
AssessSafeQ192ReductionV13(
    const SafeQ192QueryBudgetV13& budget,
    const SafeQ192ReductionPremisesV13& premises,
    double sha256d_security_floor_bits = 128.0,
    double poseidon2_security_floor_bits = 128.0);

enum class RecommendedNiropPathV1 : uint8_t {
    None = 0,
    TypedAddAbsorbCustomReduction = 1,
    IndependentOverwriteDuplex = 2,
    PublishedSafeCore = 3,
};

struct NiropPathComparisonV1 {
    TypedAddAbsorbHybridAuditV1 typed_add_absorb;
    OverwriteDuplexFsAuditV1 overwrite_duplex;
    SafeCoreMigrationAuditV1 safe_core;
    RecommendedNiropPathV1 recommended{
        RecommendedNiropPathV1::None};
    bool recommendation_preserves_current_gpu_poseidon_path{false};
    bool recommendation_is_production_selectable{false};
    std::string rationale;
};

[[nodiscard]] NiropPathComparisonV1 CompareNiropPathsV1(
    const p2::StatementV1& statement,
    const SharedPermutationBudgetV1& budget);

} // namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NIROP_HYBRID_H
