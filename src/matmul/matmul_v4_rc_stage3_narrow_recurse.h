// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NARROW_RECURSE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NARROW_RECURSE_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::narrow_recurse {

/**
 * Executable planner for a bounded-width, multi-row V_CS.
 *
 * This is deliberately not a proof system. It turns every verifier operation
 * into a scheduled row class and proves the resulting width/trace recurrence
 * with checked integer arithmetic. No AirConstraint callbacks or witness
 * builder exist here, so the readiness API must remain false until that
 * implementation is supplied and differential-tested against the native
 * verifier.
 *
 * The central layout change from air_recurse's wide V_CS is:
 *
 *   wide:   one query/row, all hash permutations side-by-side
 *   narrow: one hash permutation/lane/row, transcript values streamed
 *
 * With a fixed verifier program, operation tables are vertically packed:
 *
 *   F_width(w) = max_chip_width = 192
 *   F_width(26) = 192, and F_width(192) = 192 <= 192.
 *
 * Thus recursion reaches an explicit width fixed point without increasing the
 * backend's column cap. Operations and aggregation children consume rows, not
 * duplicated unrolled columns. Three audited lane profiles are exposed:
 *
 *   direct x^7:       width 192, gated degree 8 (recursive LDE 2^25: NO)
 *   x2/x4:            width 428, gated degree 4 (vertical-child LDE 2^25: NO)
 *   x2/x4/x6:         width 546, gated degree 3 (recursive LDE 2^24: YES)
 *
 * A separate x2/x4 fixed binary chip uses two parallel 428-column lanes
 * (width 856, degree 4) and also closes at LDE 2^24. Neither profile is an
 * executable AIR yet; the planner reports the distinction without changing a
 * backend cap.
 *
 * Design comparisons (primary sources):
 *  - STARK/AIR + FRI: https://eprint.iacr.org/2018/046
 *  - DEEP-FRI:        https://eprint.iacr.org/2019/336
 *  - Fractal:         https://eprint.iacr.org/2019/1076
 *  - Nova folding:    https://eprint.iacr.org/2021/370
 *  - Binius:          https://eprint.iacr.org/2023/1784
 *  - Circle STARKs:   https://eprint.iacr.org/2024/278
 *  - Plonky3 fixed-program recursion:
 *    https://plonky3.github.io/Plonky3-recursion/architecture_and_internals/construction.html
 *
 * The planner follows Plonky3's fixed-program/operation-table idea: local chips
 * are vertically packed and shared witness IDs would be joined through an
 * aggregated LogUp bus. That bus is not implemented here. Nova would replace
 * transparent FRI with a different folding/commitment construction; Binius
 * and Circle STARKs change the field/domain/PCS. Any of those would change
 * BTX's proof transcript and consensus semantics, so none is silently
 * substituted by this prototype.
 */

inline constexpr uint32_t kNarrowLaneColumns = 192;
inline constexpr uint32_t kNarrowMaxArity = 4;
inline constexpr uint32_t kNarrowStreamBatch = 8;
inline constexpr uint32_t kNarrowTargetSoundnessBits = 100;
inline constexpr uint32_t kNarrowVerifierBudgetMillis = 900;

enum class PoseidonLaneStrategy : uint8_t {
    DirectX7 = 0,
    DecomposedX2X4 = 1,
    DecomposedX2X4X6 = 2,
};

enum class ChildPacking : uint8_t {
    VerticalRows = 0,
    ParallelLanes = 1,
};

enum class VerifierFamily : uint8_t {
    RowMerkle = 0,
    Fold = 1,
    Deep = 2,
    PerPoint = 3,
    FiatShamirReplay = 4,
    Count = 5,
};

enum class NarrowRowKind : uint8_t {
    RowAbsorb = 0,
    MerkleCompress = 1,
    FoldLeaf = 2,
    FoldAlgebra = 3,
    DeepAccumulate = 4,
    PerPointAccumulate = 5,
    FiatShamirAbsorb = 6,
    Boundary = 7,
    Count = 8,
};

inline constexpr uint32_t kNarrowFamilyCount =
    static_cast<uint32_t>(VerifierFamily::Count);
inline constexpr uint32_t kNarrowRowKindCount =
    static_cast<uint32_t>(NarrowRowKind::Count);
inline constexpr uint32_t kNarrowMandatoryFamilyMask =
    (uint32_t{1} << kNarrowFamilyCount) - 1;

[[nodiscard]] constexpr uint32_t FamilyBit(VerifierFamily family)
{
    return uint32_t{1} << static_cast<uint32_t>(family);
}

struct ColumnRegion {
    uint32_t offset{0};
    uint32_t count{0};

    [[nodiscard]] constexpr uint32_t End() const { return offset + count; }
};

/**
 * One physical execution lane. The permutation region is exactly the existing
 * flattened 130-cell Poseidon2 witness. Everything dependent on child width
 * is streamed through rows, not allocated as columns.
 */
struct NarrowLaneLayout {
    PoseidonLaneStrategy poseidon_strategy{PoseidonLaneStrategy::DirectX7};
    ColumnRegion control;       // clock, indices, 8 row selectors, 5 family selectors
    ColumnRegion permutation;   // existing flattened Poseidon2 permutation
    ColumnRegion sbox_x2;       // 118 x^2 witnesses in decomposed mode
    ColumnRegion sbox_x4;       // 118 x^4 witnesses in decomposed mode
    ColumnRegion sbox_x6;       // 118 x^6 witnesses in fully quadratic mode
    ColumnRegion running_digest;
    ColumnRegion sibling_digest;
    ColumnRegion ext_registers; // Fp3 fold/DEEP/per-point accumulators
    ColumnRegion preprocessed;  // program/indices/domain points
    ColumnRegion scalar;
    ColumnRegion reserved;
    uint32_t width{0};

    [[nodiscard]] bool IsCanonical(std::string* why = nullptr) const;
};

[[nodiscard]] NarrowLaneLayout CanonicalNarrowLaneLayout();
[[nodiscard]] NarrowLaneLayout CanonicalNarrowLaneLayout(
    PoseidonLaneStrategy strategy);

struct PoseidonConstraintProfile {
    PoseidonLaneStrategy strategy{PoseidonLaneStrategy::DirectX7};
    uint32_t sboxes{0};
    uint32_t auxiliary_columns{0};
    uint32_t constraints{0};
    uint32_t ungated_max_degree{0};
    uint32_t selector_degree{0};
    uint32_t gated_max_degree{0};
};

/**
 * Decomposed mode constrains, for each S-box input x and output y:
 *
 *   x2 - x*x = 0
 *   x4 - x2*x2 = 0
 *   y  - x4*x2*x = 0
 *
 * The residual degree is 3. The single-table implementation gates it by the
 * permutation-row selector, so the actual AIR maximum is degree 4. The
 * selector is boolean and fixed by preprocessed row kind.
 *
 * Fully quadratic mode additionally uses:
 *
 *   x6 - x4*x2 = 0
 *   y  - x6*x = 0
 *
 * All residuals then have degree 2 and selector gating gives actual degree 3.
 */
[[nodiscard]] PoseidonConstraintProfile CanonicalPoseidonConstraintProfile(
    PoseidonLaneStrategy strategy);

struct NarrowVcsConfig {
    PoseidonLaneStrategy poseidon_strategy{PoseidonLaneStrategy::DirectX7};
    ChildPacking child_packing{ChildPacking::VerticalRows};
    uint32_t represented_family_mask{kNarrowMandatoryFamilyMask};
};

/**
 * Shape of the proof being verified by one V_CS lane. `child_constraints`
 * counts the registered per-point AIR identities to stream through the
 * composition accumulator.
 */
struct NarrowChildShape {
    uint32_t child_w{0};
    uint32_t child_n_rows{0};
    uint32_t child_n_coeffs{0};
    uint32_t child_n_lde{0};
    uint32_t merkle_depth{0};
    uint32_t n_folds{0};
    uint32_t queries{0};
    uint32_t child_constraints{0};
    uint32_t arity{2};
};

struct FamilySchedule {
    VerifierFamily family{};
    bool represented{false};
    uint64_t rows_per_query{0};
    uint64_t rows_per_child{0};
    uint32_t constraint_templates{0};
};

struct NarrowVcsPlan {
    bool valid{false};
    std::string note;
    NarrowChildShape child;
    NarrowVcsConfig config;
    NarrowLaneLayout lane;
    uint32_t represented_family_mask{0};
    std::array<FamilySchedule, kNarrowFamilyCount> families{};

    uint32_t parent_width{0};
    uint32_t recursively_planned_width{0};
    bool all_mandatory_families{false};
    bool width_fixed_point{false};

    uint64_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t constraint_templates{0};
    uint32_t max_algebraic_degree{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    bool backend_columns_supported{false};
    bool backend_lde_supported{false};
};

/** Frozen production leaf shape: episode shard N=2^16, W=26, binary root. */
[[nodiscard]] NarrowChildShape ProductionEpisodeChildShape();

/** Multi-block row-leaf sponge rows, byte-for-byte shape of SpongeHashFp. */
[[nodiscard]] uint64_t RowLeafPermutationRows(uint32_t child_w);

/** Proof-transcript sponge rows needed by a complete in-AIR FS replay. */
[[nodiscard]] uint64_t FiatShamirReplayRows(const NarrowChildShape& child);

/**
 * Build a checked deterministic schedule. Missing family bits do not make the
 * planner malformed; they make `all_mandatory_families` false and readiness
 * fail closed.
 */
[[nodiscard]] NarrowVcsPlan BuildNarrowVcsPlan(
    const NarrowChildShape& child,
    uint32_t represented_family_mask = kNarrowMandatoryFamilyMask);
[[nodiscard]] NarrowVcsPlan BuildNarrowVcsPlan(
    const NarrowChildShape& child,
    const NarrowVcsConfig& config);

/** Shape of this plan when consumed as a child at the next recursion level. */
[[nodiscard]] NarrowChildShape NextRecursiveChildShape(const NarrowVcsPlan& plan);

struct NarrowVcsCapabilities {
    bool executable_air{false};
    bool honest_witness_builder{false};
    bool native_differential_tests{false};
    bool proof_independent_fs_replay{false};
    uint32_t composed_soundness_bits{0};
    uint32_t production_verify_millis{0};
    bool consensus_authority_enabled{false};
};

struct NarrowVcsReadiness {
    bool layout_valid{false};
    bool all_mandatory_families{false};
    bool width_fixed_point{false};
    bool trace_shape_fixed_point{false};
    bool backend_shape_supported{false};
    bool implementation_complete{false};
    bool soundness_target_met{false};
    bool performance_target_met{false};
    bool production_ready{false};
    std::vector<std::string> gaps;
};

enum class SoundnessTopology : uint8_t {
    IndependentRoleRoots = 0,
    UnifiedMultiRoleRoot = 1,
};

/**
 * Conservative union-bound model. `additional_recursive_nodes` and
 * `additional_accumulation_steps` must include every separately fallible
 * proof/accumulation site; callers may not quote a per-proof bit figure as a
 * global figure without accounting for them.
 */
struct NarrowSoundnessPlan {
    SoundnessTopology topology{SoundnessTopology::IndependentRoleRoots};
    uint32_t queries{0};
    uint32_t role_roots{14};
    uint32_t additional_recursive_nodes{0};
    uint32_t additional_accumulation_steps{0};
    bool multi_role_public_pin_schema{false};
    double raw_bits{0.0};
    uint64_t union_sites{0};
    double union_loss_bits{0.0};
    double composed_bits{0.0};
    bool topology_complete{false};
    bool target_met{false};
    std::string note;
};

/**
 * Uses the repository's current unique-decoding query term:
 * Q*log2(32/17)-40. It is a parameter diagnostic, not a security proof.
 */
[[nodiscard]] NarrowSoundnessPlan AssessNarrowSoundness(
    SoundnessTopology topology,
    uint32_t queries,
    uint32_t role_roots = 14,
    uint32_t additional_recursive_nodes = 0,
    uint32_t additional_accumulation_steps = 0,
    bool multi_role_public_pin_schema = false);

/**
 * Screening model for the field/domain term exposed by the formal
 * Fiat-Shamir analysis of FRI (ePrint 2023/1071):
 *
 *   epsilon_rbr = max(O(|L|^2 / |F|), proximity_error).
 *
 * The hidden constant, rho factor, random-oracle adversary query count,
 * batching reductions, and independence proof are deliberately not hidden
 * behind a readiness flag. `formal_reduction_complete` and
 * `authority_eligible` therefore remain false.
 *
 * `fri_lanes=2` models two domain-separated FRI executions over the same
 * statement that must both accept. Under a future independence reduction,
 * this squares both modeled terms while permitting Q=96 per lane (192 total
 * queries). This is a candidate construction, not the executable backend.
 */
struct FriFormalMarginExperiment {
    uint32_t field_bits{192};
    uint32_t lde_log2{24};
    uint32_t grinding_bits{40};
    uint32_t global_site_log2{28};
    uint32_t fri_lanes{1};
    uint32_t queries_per_lane{192};
    double proximity_bits_after_losses{0.0};
    double field_domain_bits_after_losses{0.0};
    double bottleneck_bits{0.0};
    bool parameter_target_met{false};
    bool formal_reduction_complete{false};
    bool authority_eligible{false};
    std::string note;
};

[[nodiscard]] FriFormalMarginExperiment AssessFriFormalMarginExperiment(
    uint32_t fri_lanes,
    uint32_t queries_per_lane,
    uint32_t field_bits = 192,
    uint32_t lde_log2 = 24,
    uint32_t grinding_bits = 40,
    uint32_t global_site_log2 = 28);

/**
 * The batching challenge shape matters to the published Batched-FRI bound.
 *
 * IndependentCoefficients is Theorem 4.2 of ePrint 2023/1071: one independent
 * coefficient per committed function and no t factor in the displayed RBR
 * bound. SinglePowerChallenge is the communication-saving
 * (1, lambda, ..., lambda^(t-1)) variant used by the current algebraic-FRI
 * codec. Lemma 5.10 gives the exact extra factor (t-1) for that variant.
 * Applying either result still requires proving that the executable batching
 * relation is the cited protocol and deriving its actual t from a manifest.
 */
enum class FriBatchingChallengeMode : uint8_t {
    IndependentCoefficients = 0,
    SinglePowerChallenge = 1,
};

/**
 * Fail-closed concrete classical-ROM assessment for repeated FS-FRI.
 *
 * The route deliberately assessed here is:
 *
 *   1. apply BCS to each RBR-sound FRI lane;
 *   2. repeat the resulting NIROP over disjoint RO domains; and
 *   3. accept iff every lane accepts.
 *
 * ePrint 2023/1071, Theorem 4.1 and Theorem 3.15 give
 *
 *   epsilon_rbr = max(
 *       (m+1/2)^7 |L|^2 / (3 rho^(3/2) |F|),
 *       (1-delta)^ell)
 *   epsilon_fs(Q) <= Q epsilon_rbr + 3(Q^2+1)/2^kappa.
 *
 * ePrint 2016/116, Appendix B.2, Lemma B.1 gives the repeated NIROP
 * upper bound epsilon_rep(Q) <= epsilon_fs(Q)^r when the r oracle domains
 * are disjoint. Under the concrete work metric in ePrint 2024/1161,
 * Definition 2, the conditional work screen at one declared Q is
 *
 *   log2(Q / (S epsilon_rep(Q)))
 *     = log2 Q - log2 S - log2 epsilon_rep(Q).
 *
 * Consequently the leading Q loss is charged once after a two-lane square,
 * not twice. This is different from quoting fixed-Q acceptance-probability
 * bits, and the two metrics must not be interchanged. Definition 2 requires
 * the inequality for every Q; a single Q=2^40 evaluation is not itself a
 * Definition-2 theorem.
 *
 * Numeric results remain a screen. The current codec has lane prefixes and an
 * accept-all verifier, but the full transcript-domain disjointness proof,
 * executable batching-protocol correspondence, manifest-derived batch width,
 * enforced Q/S budgets, complete BCS instantiation, and global reduction are
 * open. In addition, the lanes share one algebraic row commitment. Its
 * binding/collision failure is a common non-squared term and needs a separate
 * hybrid reduction. Readiness therefore remains false regardless of the
 * numeric result.
 */
struct FriBcsRepetitionAssessment {
    uint32_t fri_lanes{0};
    uint32_t queries_per_lane{0};
    uint32_t field_bits{0};
    uint32_t lde_log2{0};
    uint32_t rate_inverse_log2{0};
    uint32_t list_parameter_m{0};
    uint32_t adversary_query_log2{0};
    uint32_t global_site_log2{0};
    uint32_t random_oracle_output_bits{0};
    uint32_t batch_columns_upper_bound{0};
    uint32_t uniform_sampler_words_per_draw{0};
    uint32_t uniform_sampler_required_valid_words{0};
    uint32_t challenge_draws_per_lane_upper_bound{0};
    uint32_t manifest_challenge_draws_per_lane{0};
    FriBatchingChallengeMode batching_mode{
        FriBatchingChallengeMode::SinglePowerChallenge};

    double theorem_constant_loss_bits{0.0};
    double batching_loss_bits{0.0};
    double field_rbr_bits{0.0};
    double proximity_rbr_bits{0.0};
    double lane_rbr_bits{0.0};
    double lane_bcs_query_term_bits{0.0};
    double lane_bcs_ro_collision_bits{0.0};
    double lane_fs_soundness_bits{0.0};
    /** Conditional fixed-Q screen before the proof-site union. */
    double repeated_work_bits_before_sites{0.0};
    /** Conditional fixed-Q screen after the proof-site union. */
    double global_work_bits{0.0};
    /** All-Q Definition-2 screen for the Q*epsilon_rbr branch. */
    double all_query_rbr_branch_work_bits{0.0};
    /** All-Q Definition-2 screen for the BCS RO-collision branch. */
    double all_query_ro_branch_work_bits{0.0};
    /** Minimum of the two all-Q screens, still conditional on open hybrids. */
    double all_query_work_screen_bits{0.0};
    /** Statistical-distance cap for the legacy uint64-mod-p Fp3 draw. */
    double legacy_modulo_bias_bits{0.0};
    /** -log2 probability that one 64-bit word is not a canonical Fp limb. */
    double uniform_limb_rejection_bits{0.0};
    /** -log2 probability that the fixed word pool has fewer than 3 limbs. */
    double uniform_sampler_exhaustion_bits_per_draw{0.0};
    /** Completeness floor after lanes, declared draw budget and proof sites. */
    double uniform_sampler_global_completeness_bits{0.0};
    /** Statistical-distance cap for legacy uniform-Fp then `% 2^k`. */
    double legacy_query_index_bias_bits{0.0};
    /** Diagnostic floor only; it is not a certified security claim. */
    uint32_t conservative_floor_bits{0};
    /** Always zero until every reduction/precondition below is discharged. */
    uint32_t certified_bits{0};
    uint32_t all_query_conservative_floor_bits{0};

    bool fri_rbr_parameter_domain_valid{false};
    bool published_batching_constant_exact{false};
    bool batching_protocol_instantiation_proven{false};
    bool batch_columns_manifest_derived{false};
    bool bcs_bound_numerically_accounted{false};
    bool nirop_repetition_theorem_available{false};
    bool executable_dual_lane_shape_present{false};
    bool lane_statement_equality_enforced{false};
    bool accept_all_lanes_enforced{false};
    bool lane_domain_prefixes_present{false};
    /** Every RO call, not merely FS challenges, has a disjoint lane prefix. */
    bool all_random_oracle_calls_lane_prefixed{false};
    /** Shared AlgHash commitment binding is a separate, non-squared event. */
    bool common_commitment_binding_quantitatively_accounted{false};
    bool common_commitment_hybrid_reduction_complete{false};
    /** Exact for the executable dual-Q128 V5 path. */
    bool uniform_field_challenge_sampling_present{false};
    bool uniform_sampler_draw_bound_manifest_derived{false};
    bool power_of_two_query_domain_enforced{false};
    bool uniform_query_index_sampling_present{false};
    bool fixed_schedule_uniform_ood_sampling_present{false};
    bool transcript_domains_proven_disjoint{false};
    bool adversary_query_bound_enforced{false};
    /** Definition 2 requires the work inequality for every Q, not one Q. */
    bool definition2_all_query_budgets_proven{false};
    bool global_site_bound_manifest_derived{false};
    bool formal_reduction_complete{false};
    bool parameter_target_met{false};
    bool all_query_parameter_target_met{false};
    bool authority_eligible{false};
    std::string note;
};

[[nodiscard]] FriBcsRepetitionAssessment AssessFriBcsRepetition(
    uint32_t fri_lanes = 2,
    uint32_t queries_per_lane = 128,
    uint32_t field_bits = 192,
    uint32_t lde_log2 = 24,
    uint32_t rate_inverse_log2 = 4,
    uint32_t list_parameter_m = 3,
    uint32_t adversary_query_log2 = 40,
    uint32_t global_site_log2 = 28,
    uint32_t random_oracle_output_bits = 256,
    uint32_t batch_columns_upper_bound = 1U << 14,
    FriBatchingChallengeMode batching_mode =
        FriBatchingChallengeMode::IndependentCoefficients,
    uint32_t uniform_sampler_words_per_draw = 8,
    uint32_t uniform_sampler_required_valid_words = 3,
    // V5 maximum: 2^14 independent batching draws + 4 OOD candidates +
    // two DEEP weights + 20 folds at the 2^24 LDE cap.
    uint32_t challenge_draws_per_lane_upper_bound = (1U << 14) + 26);

enum class FriDualCommitmentTopology : uint8_t {
    SharedMaster = 0,
    FullyDuplicatedLanes = 1,
    /**
     * Experimental V1 screen: commit the same row matrix under two ordered,
     * independently domain-separated AlgHash roots and bind both lane
     * transcripts to the ordered pair.  The executable construction and an
     * independence reduction are deliberately not implied by this enum.
     */
    TwoCommonRoots = 2,
};

/**
 * Exact-site numerical composition of the conditional dual-Q128 all-query
 * FRI screen with its non-squared AlgHash binding event.
 *
 * If a and b are the two error exponents, the composed exponent is
 *   -log2(2^-a + 2^-b),
 * not min(a,b).  Fully duplicated lane commitments conservatively charge two
 * binding events.  This remains a parameter screen: the manifest is not yet
 * enforced by the executable backend and the commitment/NIROP reductions are
 * still open.
 */
struct FriDualQ128HybridBoundAssessment {
    FriDualCommitmentTopology topology{
        FriDualCommitmentTopology::SharedMaster};
    uint64_t global_site_count{0};
    uint32_t binding_events_per_site{0};
    double global_site_log2{0.0};
    double fri_all_query_bits{0.0};
    double commitment_binding_bits{0.0};
    /** What the binding exponent would be if simultaneous collisions in the
     * two ordered roots were proved independent.  Diagnostic only. */
    double independence_amplified_binding_bits{0.0};
    double composed_union_bits{0.0};
    bool parameters_valid{false};
    bool numerical_target_met{false};
    bool two_common_root_backend_executable{false};
    bool binding_independence_reduction_complete{false};
    bool exact_site_manifest_backend_enforced{false};
    bool commitment_hybrid_reduction_complete{false};
    bool formal_reduction_complete{false};
    bool authority_eligible{false};
    std::string note;
};

[[nodiscard]] FriDualQ128HybridBoundAssessment
AssessFriDualQ128HybridBound(
    uint64_t global_site_count,
    FriDualCommitmentTopology topology =
        FriDualCommitmentTopology::SharedMaster);

/**
 * Replans two recursive levels to check both F_width(W*) <= W* and stabilization
 * of the padded trace length. Production readiness additionally requires the
 * missing executable AIR, witness, differential, FS, soundness and benchmark
 * capabilities; the current tree intentionally supplies none of them.
 */
[[nodiscard]] NarrowVcsReadiness AssessNarrowVcsReadiness(
    const NarrowVcsPlan& leaf_plan,
    const NarrowVcsCapabilities& capabilities = {});

inline constexpr bool kNarrowVcsExecutable = false;
inline constexpr bool kNarrowVcsProductionReady = false;

} // namespace matmul::v4::rc::narrow_recurse

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NARROW_RECURSE_H
