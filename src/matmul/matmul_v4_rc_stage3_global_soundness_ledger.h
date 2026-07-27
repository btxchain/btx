// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_GLOBAL_SOUNDNESS_LEDGER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_GLOBAL_SOUNDNESS_LEDGER_H

#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::global_soundness_ledger {

inline constexpr uint16_t kExecutableGlobalLedgerVersion = 1;
inline constexpr uint64_t kCanonicalProductionSites =
    37'488'397ULL;
inline constexpr uint32_t kRelationLocalProofInstances = 326;
inline constexpr uint64_t kConservativeProductSites =
    12'221'217'422ULL;
inline constexpr uint32_t kSelectedSingleLaneQueries = 192;
inline constexpr uint32_t kSelectedExtensionDegree = 3;
inline constexpr uint32_t kSelectedLdeLog2 = 24;
inline constexpr uint32_t kConservativeGrindingBits = 40;
inline constexpr uint32_t kConservativeFp3Bits = 189;
inline constexpr uint32_t kHashCollisionFloorBits = 128;
inline constexpr uint32_t kFsSamplerFailureBits = 187;
inline constexpr uint32_t kCtlBusesPerSiteEnvelope = 52;
inline constexpr uint32_t kCtlEventsPerBusEnvelope = 1U << 24;
inline constexpr uint32_t kFsSamplerDrawsPerCtlBus = 25;

// --- #1 statement-decomposition bridge (PR-89) ---------------------------
// The arity-4 relation-local recursion tree over which the straight-line ROM
// extractor composes ADDITIVELY. The confirmed shape is 244 shards -> 256
// leaves (4^4) + 85 internal aggregation nodes = 341 nodes. The bridge proved
//   Pr[accept ^ false] <= 341*kappa + 2^-128 + 2^-88 + eps_P2,
// i.e. a single additive union charge of +log2(341) over the tree, with NO
// depth-multiplicative (nested rewinding) loss.
inline constexpr uint32_t kBridgeRecursionLeafNodes = 256;
inline constexpr uint32_t kBridgeRecursionInternalNodes = 85;
inline constexpr uint32_t kBridgeRecursionTotalNodes =
    kBridgeRecursionLeafNodes + kBridgeRecursionInternalNodes; // 341
inline constexpr uint32_t kBridgeRecursionAggregationArity = 4;
/** 2^-128 generic hash-collision floor term of the bridge bound. */
inline constexpr double kBridgeHashCollisionBits = 128.0;
/** 2^-88 SHA256d cross-hash term (128-bit birthday minus the 40-bit grind). */
inline constexpr double kBridgeCrossHashShaBits = 88.0;

/**
 * g5 (self-similar fixed point), first conjunct: whether the full-arity
 * (four-slot, arity-4) parent-own-FRI round trip is proven-and-verified
 * EVIDENCE this assessor itself can stand behind, as opposed to a frozen
 * prose comment describing a run that happened once elsewhere.
 *
 * POLICY (documented here because the struct enforces it, not a header
 * comment elsewhere): the same four-slot self-similar parent shape used by
 * `four_slot_self_similar_parent_own_fri_fits_alg_column_cap`
 * (matmul_v4_rc_stage3_recursive_parent_air_tests.cpp) is built EVERY call —
 * that build is cheap (a two-row toy child proof plus one in-AIR parent
 * construction, no FRI prove of the parent) and runs unconditionally in the
 * default gate, so `column_cap_admits` is always live-computed, never a
 * literal. The actual parent-own-FRI SELF-PROVE is CPU-heavy (tens of
 * minutes; ~15 GiB peak at this toy shape, see the test file) and is
 * therefore run ONLY under the SAME `BTX_RUN_HEAVY_PARENT_FRI` environment
 * gate the test suite already uses — but unlike the retired recursive.cpp
 * `constexpr true`, when that gate is set this assessor RECOMPUTES the
 * proof/verify/tamper-reject/wrong-seed-reject round trip live, right here,
 * every time it is asked; it never trusts a comment or a cached historical
 * observation. Absent the env gate, `full_arity_in_default_gate` stays
 * honestly false — this assessor exports recomputable evidence rather than
 * claiming affordability it does not have.
 */
struct ParentOwnFriFullArityAssessmentV1 {
    uint32_t parent_columns{0};
    uint32_t backend_column_cap{0};
    /** Live-computed every call; the toy four-slot parent V_CS build is
     * cheap and always runs, so this is never a hard-coded literal. */
    bool column_cap_admits{false};
    /** True iff BTX_RUN_HEAVY_PARENT_FRI was set when this ran. */
    bool heavy_gate_enabled{false};
    /** True iff the heavy self-prove path actually executed this call
     * (implies heavy_gate_enabled and a valid toy four-slot parent). */
    bool full_arity_proof_recomputed_this_run{false};
    bool full_arity_proof_produced{false};
    bool full_arity_proof_verified{false};
    bool tamper_and_wrong_seed_rejected{false};
    /** The exported conjunct: only true when the heavy round trip was
     * RECOMPUTED live this call (not merely admitted by the cap) and it
     * produced, verified, and rejected both tamper and wrong-seed variants.
     * False whenever BTX_RUN_HEAVY_PARENT_FRI is unset, i.e. in the default
     * gate — that is the honest answer this PR closes: it was `false`
     * unconditionally before; it is now a computed, recomputable `false`
     * (or a genuinely re-earned `true` under the heavy env gate). */
    bool full_arity_in_default_gate{false};
    std::string note;
};

[[nodiscard]] ParentOwnFriFullArityAssessmentV1
AssessParentOwnFriFullArityV1();

enum class ExecutableGlobalTermKindV1 : uint8_t {
    FriBcs = 1,
    TraceBatching = 2,
    ConstraintBatching = 3,
    CtlRationalIdentity = 4,
    HashBinding = 5,
    FiatShamirSampler = 6,
    FiatShamirReplayAndNirop = 7,
    PowGrinding = 8,
};

struct ExecutableGlobalTermV1 {
    ExecutableGlobalTermKindV1 kind{};
    double conditional_bits{0.0};
    bool quantitatively_accounted{false};
    /** False for completeness/liveness and accounting-only terms. */
    bool included_in_false_accept_union{false};
    bool completeness_or_liveness_only{false};
    bool implementation_executable{false};
    bool reduction_complete{false};
    std::string prerequisite;
};

/**
 * One site-count screen. `known_false_accept_union_bits` is the exact
 * additive union of the conditional FRI, trace batching, constraint
 * batching, CTL and hash terms below. It deliberately excludes FS sampler
 * exhaustion (liveness) and PoW grinding (already charged into algebraic
 * challenge terms under the total-work convention).
 */
struct ExecutableGlobalSiteScenarioV1 {
    uint64_t sites{0};
    double site_log2{0.0};
    bool site_count_manifest_derived{false};
    bool covers_selected_relation_local_topology{false};
    bool production_theorem{false};

    double q192_fri_bcs_bits{0.0};
    double maximum_single_lane_fri_bcs_bits{0.0};
    uint32_t fri_saturation_queries{0};
    /** Zero means no single-lane Q can meet 100 bits under this site count. */
    uint32_t minimum_numeric_q_for_fri_100{0};
    bool fri_100_reachable_by_any_single_lane_q{false};
    /** Q=192 is the only selected executable Split-RAP query shape. */
    uint32_t minimum_currently_executable_q_for_fri_100{0};

    double trace_batching_bits{0.0};
    double constraint_batching_bits{0.0};
    double ctl_rational_identity_bits{0.0};
    double hash_binding_bits{0.0};
    double fs_sampler_liveness_bits{0.0};
    double known_false_accept_union_bits{0.0};
    bool known_union_numeric_target_met{false};
    std::vector<ExecutableGlobalTermV1> terms;
};

struct ExecutableRelationRowsPolicyScenarioV1 {
    uint8_t hash_parallel_lanes{0};
    uint32_t relation_rows_per_site{0};
    uint64_t relation_leaf_sites{0};
    uint64_t arity_four_parent_sites{0};
    uint64_t final_tree_parent_sites{0};
    uint64_t total_sites{0};
    bool finite_manifest_derived{false};
    bool row_cap_supported_by_registered_builders{false};
    bool hash_vector_shape_supported{false};
    bool hash_proof_wrapper_executable{false};
    bool production_memory_profile_measured{false};
    bool recursive_scheduler_enforces_policy{false};
    bool production_selectable{false};
    ExecutableGlobalSiteScenarioV1 additive;
};

/**
 * Strongest honest numeric ledger for the selected executable
 * single-Fp3/Q192 Split-RAP primitive. The selected 2^18 shard schedule is a
 * complete accounting fallback, not an economically viable production
 * prover topology. The family-batched alternative is reported separately
 * and remains non-executable.
 *
 * The conservative product is intentionally a diagnostic, not a topology
 * theorem. All certificate/authority counters stay zero until the complete
 * normalized verifier, semantic CTLs, exact site topology, FS/NIROP
 * composition, hash hybrid and PoW theorem execute end to end.
 */
/**
 * Ordered interlock that gates flipping the live `certified_bits` off zero.
 * Each member mirrors one honest current-state readiness flag; the composed
 * floor becomes certified ONLY when every member is true (via genuine passing
 * tests / landed constructions). No member is flipped by this ledger.
 *
 * Ordered gate list. The index is PRESENTATIONAL, not causal: the real causal
 * order runs the other way (gate 4 -> gate 5 -> gate 2 -> gate 1 -> gate 0),
 * and gate 4 is the single live root blocker for gates 0, 1, 2 and 5.
 *
 * Every member is the AND of its honest readiness constant and an INDEPENDENT
 * evidence predicate recomputed from the tree. That conjunction is strictly
 * fail-closed — it can only ever remove a `true` — so flipping a readiness
 * constant on its own no longer closes a gate.
 *
 *   0 mathematical_verifier_ready       kRCStage3MathematicalVerifierReady
 *                                       && gate 1 && coupled engines ready
 *                                       (the verifier calls episode relations
 *                                       unconditionally, so g0 <= g1)
 *   1 episode_relations_ready           kRCStage3EpisodeRelationsReady
 *                                       && episode relation gap report empty
 *   2 recursive_aggregation_ready       kRCStage3RecursiveAggregationReady
 *                                       && gate 4 (recursive.cpp's own
 *                                       cryptographic_verification_ready
 *                                       depends on it)
 *                                       && every role a Composed statement
 *                                          requires is in-CS closable through
 *                                          the immutable registry
 *                                       && the two-level root verify is
 *                                          representable, produced and MEASURED
 *                                          inside the 900 ms relay budget
 *                                          (CurrentRCStage3TwoLevelRootVerify-
 *                                           BudgetV1().within_relay_budget)
 *                                       The last two are g2's OWN blockers:
 *                                       without them g2 reduced entirely to
 *                                       "constant && gate 4".
 *   3 fri_alg_formal_soundness_ready    kRCFri3AlgFormalSoundnessReady
 *                                       && AssessFri3AlgBcsRbrLedgerV1()
 *                                          .rbr_reduction_machine_checked
 *   4 child_fiat_shamir_replay_closed   AssessChildFsReplayClosureV1().closed
 *                                       (SHA-FS chip lane; ledger FS-replay)
 *   5 self_similar_fixed_point_closed   AssessParentOwnFriFullArityV1()
 *                                       .full_arity_in_default_gate && gate 4;
 *                                       the first conjunct is COMPUTED (cap
 *                                       admission is live every call; the
 *                                       heavy self-prove is recomputed live
 *                                       only under BTX_RUN_HEAVY_PARENT_FRI)
 *                                       and stays false in the default gate,
 *                                       never a bare literal (see the .cpp
 *                                       note on the divergence from
 *                                       recursive.cpp)
 *   6 global_soundness_composition_proved (global additive theorem)
 */
struct CompositionReadinessGateV1 {
    bool mathematical_verifier_ready{false};
    bool episode_relations_ready{false};
    bool recursive_aggregation_ready{false};
    bool fri_alg_formal_soundness_ready{false};
    bool child_fiat_shamir_replay_closed{false};
    bool self_similar_fixed_point_closed{false};
    bool global_soundness_composition_proved{false};
    /** Conjunction of all seven gates above. */
    bool all_clear{false};
};

/**
 * Executable, machine-checked encoding of the global additive composition
 * theorem (gate 6 / global_soundness_composition_proved). It MACHINE-COMPUTES
 * the global certified_bits from the four proven audit-input components:
 *
 *   (a) the per-node extractor bridge: 341*kappa additive union over the
 *       relation-local recursion tree (straight-line ROM extraction; the loss
 *       is ADDITIVE +log2(341), never depth-multiplicative);
 *   (b) the dual-lane A2 field-pair / query-pair / shared-collision terms,
 *       whose binding minimum is the per-node extractor error kappa = F(q*);
 *   (c) the flat M-LINK/P2 + cross-hash (2^-88) + hash-collision (2^-128)
 *       terms (a single collision breaks globally, so they do not union);
 *   (d) the site-union charge over the canonical production site count.
 *
 * Composition uses the same log-sum-exp union / min-floor arithmetic as the
 * rest of the ledger and reproduces the shipped composed-floor global (79).
 * This struct is a machine-checked COMPUTATION; it does not by itself mint
 * certified bits (that is gated on the readiness interlock).
 */
struct ExecutableGlobalAdditiveCompositionV1 {
    // (a) #1 statement-decomposition bridge.
    uint32_t recursion_leaf_nodes{0};
    uint32_t recursion_internal_nodes{0};
    uint32_t recursion_total_nodes{0};
    uint32_t recursion_tree_depth{0};
    double recursion_node_union_log2_bits{0.0};
    double per_node_extractor_kappa_bits{0.0};
    double bridge_additive_union_bits{0.0};
    /** The rejected depth-multiplicative (nested-rewinding) alternative. */
    double depth_multiplicative_comparison_bits{0.0};
    bool extraction_loss_is_additive_not_multiplicative{false};

    // (b) dual-lane A2 exponents at q*.
    double field_pair_bits{0.0};
    double taxed_query_pair_bits{0.0};
    double shared_collision_bits{0.0};
    double dual_lane_binding_kappa_bits{0.0};

    // (c) flat M-LINK + cross-hash + hash-collision terms.
    double mlink_p2_epsilon_bits{0.0};
    double cross_hash_sha_bits{0.0};
    double hash_collision_bits{0.0};
    double flat_hash_link_lse_bits{0.0};

    // (d) site-union charge.
    uint64_t global_sites{0};
    double site_union_charge_exact_bits{0.0};
    double site_union_charge_bits{0.0};
    double site_union_charged_floor_bits{0.0};

    /** Per-proof bridge bound = 341*kappa + 2^-128 + 2^-88 + eps_P2 (lse). */
    double per_proof_bridge_bound_bits{0.0};
    /** min( site-union-charged per-node floor, per-proof bridge bound ). */
    double global_composed_bits{0.0};
    uint32_t global_certified_bits_target{0};

    bool union_arithmetic_consistent{false};
    bool global_matches_shipped_composed_floor{false};
    /** M2 Poseidon2 binding is an inherent, non-removable audit assumption. */
    bool poseidon2_binding_is_explicit_assumption{false};
    /** True iff the executable composition genuinely composes + self-checks. */
    bool machine_checked{false};
    std::string note;
};

[[nodiscard]] ExecutableGlobalAdditiveCompositionV1
ComposeExecutableGlobalAdditiveBoundV1(
    const soundness_scenarios::ComposedThreatModelFloorV1& composed_floor,
    double mlink_p2_epsilon_bits);

struct ExecutableGlobalSoundnessLedgerV1 {
    uint16_t version{kExecutableGlobalLedgerVersion};
    uint32_t selected_queries{kSelectedSingleLaneQueries};
    uint32_t extension_degree{kSelectedExtensionDegree};
    uint32_t lde_log2{kSelectedLdeLog2};
    uint32_t grinding_bits{kConservativeGrindingBits};
    uint32_t trace_width_cap{0};
    uint32_t constraint_count_cap{0};
    uint32_t ctl_buses_per_site_envelope{
        kCtlBusesPerSiteEnvelope};
    uint32_t ctl_events_per_bus_envelope{
        kCtlEventsPerBusEnvelope};

    bool single_fp3_backend_executable{false};
    bool q192_multirow_v2_executable{false};
    bool q192_split_rap_integrated{false};
    bool ctl_dual_lane_arithmetic_executable{false};
    /** All recursive verifier, child-cell transport and CTL accumulator
     * values use Fp3. The retired Fp2 transport-floor analysis is therefore
     * not a term in this ledger. */
    bool recursive_child_transport_fp3_only{false};
    bool legacy_fp2_transport_bound_inapplicable{false};
    bool hash_primitives_executable{false};
    bool grinding_parameter_executable{false};
    /** The 40-bit charge is the proof-internal FS/FRI query grind. It is kept
     * separate from mining a fresh tensor-PoW statement. */
    bool internal_fri_grinding_charged{false};
    /** The FVT terminal-round recompute is documented but is not executed by
     * the sampled-carrier verifier. Stage-3 cannot claim it as a theorem
     * premise; complete relation closure must bind the full computation. */
    bool sampled_terminal_round_fvt_executable{false};
    bool external_pow_work_composition_complete{false};

    ExecutableGlobalSiteScenarioV1 canonical;
    ExecutableGlobalSiteScenarioV1 conservative_product;
    /** Numeric-only candidate with one quotient/FRI receipt per family plus
     * arity-four role reductions. Rows are internal theorem events, not
     * independent per-shard proof failures. */
    ExecutableGlobalSiteScenarioV1 family_batched_candidate;
    uint64_t family_batched_proof_instances{0};
    bool shard_tree_economically_production_candidate{false};
    bool family_linear_fold_executable{false};
    bool family_zero_residual_fold_executable{false};
    bool family_fold_proof_codec_executable{false};
    bool nonlinear_trace_fold_explicitly_rejected{false};
    bool family_residual_bound_to_constraint_vm{false};
    bool family_batched_rows_absorbed_by_relation_theorems{false};
    bool family_batched_single_quotient_fri_executable{false};
    std::vector<ExecutableRelationRowsPolicyScenarioV1>
        relation_rows_policies;

    bool semantic_relation_closure_complete{false};
    bool normalized_recursive_verifier_executable{false};
    bool exact_selected_topology_manifest_derived{false};
    bool canonical_heterogeneous_site_topology_derived{false};
    bool deprecated_width_product_rejected{false};
    bool universal_program_registry_binding_defined{false};
    bool universal_program_registry_consumed_in_recursion{false};
    bool ali_degree_and_constraint_manifest_complete{false};
    bool ctl_export_and_terminal_reduction_complete{false};
    bool hash_first_collision_hybrid_complete{false};
    bool fiat_shamir_replay_complete{false};
    bool self_similar_fixed_point_closed{false};
    bool nirop_oracle_separation_complete{false};
    bool pow_composition_theorem_complete{false};
    bool global_additive_theorem_complete{false};

    /** Composed threat-model floor F(q*) + explicit audit-input assumptions. */
    soundness_scenarios::ComposedThreatModelFloorV1 composed_floor;
    /** Executable, machine-checked global additive composition (gate 6). */
    ExecutableGlobalAdditiveCompositionV1 global_additive_composition;
    /** True iff `global_additive_composition` genuinely composes + self-checks;
     * this is the composition half of gate 6 (the other half is gates 0-5). */
    bool global_additive_composition_machine_checked{false};
    /** Ordered readiness interlock; `all_clear` gates the live value. */
    CompositionReadinessGateV1 composition_gate;
    /** Per-site composed floor F(q*) = 104 at q* = 76 (binding: 256-2q). */
    uint32_t per_site_composed_floor_bits{0};
    /** Global (site-union charged) composed floor ~79; the value certified_bits
     * yields the moment `composition_gate.all_clear` becomes true. Computed
     * unconditionally so the ledger is correct now; not itself certified. */
    uint32_t composed_certified_bits_target{0};

    bool theorem_complete{false};
    /** Live certified soundness. Stays 0 until composition_gate.all_clear, then
     * equals composed_certified_bits_target. Never a hard-coded zero. */
    uint32_t certified_bits{0};
    bool authority_eligible{false};
    std::string note;
};

[[nodiscard]] ExecutableGlobalSoundnessLedgerV1
AssessExecutableGlobalSoundnessLedgerV1(
    uint32_t constraint_count_cap = 1U << 14);

inline constexpr bool kExecutableGlobalSoundnessCertified = false;
inline constexpr bool kExecutableGlobalSoundnessAuthorityReady = false;

} // namespace matmul::v4::rc::global_soundness_ledger

#endif
