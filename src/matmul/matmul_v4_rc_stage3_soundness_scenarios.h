// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SOUNDNESS_SCENARIOS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SOUNDNESS_SCENARIOS_H

#include <matmul/matmul_v4_rc_stage3.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::soundness_scenarios {

inline constexpr uint32_t
    kSelectedProductionRelationRowsPerSiteV1 = 1U << 18;
inline constexpr uint8_t
    kSelectedProductionHashParallelLanesV1 = 4;

enum class BatchChallengeShape : uint8_t {
    IndependentCoefficients = 1,
    SinglePower = 2,
};

/**
 * Exact counts derivable from the currently registered profile-2 relation
 * layouts.  They deliberately distinguish a lower-level obligation count
 * from a complete global upper bound.
 *
 * The 29-site normalized tree inventory is exact.  The signed-range partition
 * is also exact: every range shard needs its own range AIR plus
 * producer/consumer CTL child AIRs if the current construction is retained.
 * These legacy counts alone cannot be promoted to a global upper bound; use
 * ProductionProofSiteManifest below for the conditional all-relation bound.
 */
struct ProductionSiteInventory {
    uint64_t gemm_layers{0};
    uint64_t gemm_cells{0};
    uint64_t extract_tiles{0};
    uint64_t signed_range_shards{0};
    uint64_t scale_schedule_shards{0};
    uint64_t range_ctl_child_air_invocations{0};
    uint64_t known_leaf_air_invocations{0};
    uint64_t final_tree_sites{0};
    uint64_t known_sites_including_final_tree{0};
    uint32_t known_sites_log2_ceiling{0};
    uint64_t declared_candidate_site_budget{0};
    uint32_t declared_candidate_site_log2{0};
    uint64_t complete_global_site_upper_bound{0};
    uint64_t conditional_stage3_site_upper_bound{0};
    uint32_t conditional_stage3_site_log2{0};
    uint32_t conditional_rejection_blocks_per_32_outputs{0};

    bool profile2_layout_exact{false};
    bool final_tree_manifest_exact{false};
    bool known_sites_fit_declared_budget{false};
    bool complete_global_upper_bound_manifest_derived{false};
    bool conditional_stage3_upper_bound_manifest_derived{false};
    bool declared_budget_enforced_by_executable_backend{false};
};

/**
 * Compact, verifier-recomputable site manifest.  `logical_units` is a checked
 * upper bound on the complete public workload assigned to a relation (rows,
 * hash-compressions, or fixed relation executions); `units_per_site` is a
 * protocol cap and
 * `proof_sites=ceil(logical_units/units_per_site)`.
 *
 * The manifest is deliberately count-only.  It cannot make an absent proof
 * engine sound, but it prevents a future engine from silently omitting a
 * relation family or charging a smaller union bound than its declared
 * sharding policy.
 */
enum class ProductionProofSiteKind : uint8_t {
    EpisodeBuilderCounterXof = 1,
    EpisodeGemmSumcheck = 2,
    EpisodeGemmOpenings = 3,
    EpisodeSignedRange = 4,
    EpisodeRangeExtractCtl = 5,
    EpisodeExtractCore = 6,
    EpisodeScaleSha = 7,
    EpisodeExtractChaCha = 8,
    EpisodeWiring = 9,
    EpisodeTileTreeSha256d = 10,
    EpisodeDigestSha256d = 11,
    CoupledBankCounterXof = 12,
    CoupledBankCommitmentSha256d = 13,
    CoupledBank = 14,
    CoupledLobeInitCounterXof = 15,
    CoupledPageScheduleXof = 16,
    CoupledGemm = 17,
    CoupledExchange = 18,
    CoupledExchangeXof = 19,
    CoupledPermutation = 20,
    CoupledPermutationXof = 21,
    CoupledMix = 22,
    CoupledMixXof = 23,
    CoupledExtractCore = 24,
    CoupledExtractScaleSha = 25,
    CoupledExtractChaCha = 26,
    CoupledBarrierSha256d = 27,
    CoupledDigestSha256d = 28,
};

struct ProductionProofSiteEntry {
    ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    uint64_t logical_units{0};
    uint64_t units_per_site{0};
    uint64_t proof_sites{0};

    bool operator==(const ProductionProofSiteEntry&) const = default;
};

/**
 * Executable proof-owned fixed-program capacities.
 *
 * These are intentionally distinct from both the maximum trace height and
 * the public-boundary four-lane direct product.  The production semantic
 * product uses private boundary cells: its SHA split-RAP child reserves
 * auxiliary sink instances and therefore accepts at most 32 sources, while
 * its ChaCha child currently proves exactly one source so the internal-SSA
 * bus remains private and self-contained.
 *
 * A site inventory may charge no more than these capacities until an
 * executable private packed proof replaces them.
 */
inline constexpr uint32_t
    kProductionPrivateShaSourcesPerProofSiteV1 = 32;
inline constexpr uint32_t
    kProductionPrivateChaChaSourcesPerProofSiteV1 = 1;

/**
 * Candidate Stage-3 sharding policy.  The current episode computation has
 * unbounded rejection loops, so `max_rejection_blocks_per_32_outputs=0`
 * faithfully represents the existing protocol and cannot produce a finite
 * manifest.  A nonzero value is a proposed Stage-3 completeness rule:
 * proof generation fails if a 32-output group needs more blocks.
 *
 * This policy does not alter the currently inactive production solver.
 */
struct ProductionProofSitePolicy {
    uint16_t version{1};
    uint32_t relation_rows_per_site{1U << 16};
    uint32_t hash_program_rows_per_instance{1U << 10};
    uint32_t max_air_trace_rows{1U << 20};
    uint32_t max_rejection_blocks_per_32_outputs{0};
    /** Independent fixed-program boundary AIRs packed horizontally into one
     * quotient trace.  Lane 4 is the selected executable V1 direct product;
     * lane 1 preserves the pre-packing accounting scenario. */
    uint8_t hash_parallel_lanes{1};
    uint8_t aggregation_arity{4};

    bool operator==(const ProductionProofSitePolicy&) const = default;
};

struct ProductionProofSiteManifest {
    ProductionProofSitePolicy policy{};
    std::vector<ProductionProofSiteEntry> entries;
    uint64_t relation_leaf_sites{0};
    uint64_t below_root_aggregation_sites{0};
    uint64_t final_tree_aggregation_sites{0};
    uint64_t total_proof_sites{0};
    uint64_t union_bound_cap{0};
    uint32_t union_bound_log2{0};
    uint256 commitment{};

    bool arithmetic_exact{false};
    bool all_registered_roles_covered{false};
    bool rejection_loops_bounded{false};
    bool backend_shape_supported{false};
    /** The selected lane count has an executable boundary-bound quotient
     * construction within the normalized recursive width cap. */
    bool executable_hash_parallel_packing{false};
    /** Every hash-family units-per-site value is capped by the proof-owned
     * private-boundary backend which production semantic closure consumes. */
    bool executable_private_hash_site_capacity{false};
    /** MxExpand SHA, builder counter-XOF and Extract ChaCha witness
     * construction all stop at the selected V1 rejection cap. */
    bool executable_rejection_paths_enforce_policy{false};
    /** The normalized recursive scheduler validates this exact committed
     * manifest before accepting children.  Still false. */
    bool recursive_scheduler_consumes_manifest{false};
    bool executable_backend_enforces_policy{false};
    bool complete_global_upper_bound_manifest_derived{false};

    bool operator==(const ProductionProofSiteManifest&) const = default;
};

struct ProductionProofSiteScenario {
    std::string name;
    ProductionProofSitePolicy policy{};
    uint64_t total_proof_sites{0};
    uint64_t union_bound_cap{0};
    uint32_t union_bound_log2{0};
    bool finite{false};
    bool recursive_arity_supported{false};
    bool selected{false};
    std::string note;
};

[[nodiscard]] ProductionProofSitePolicy
SelectedProductionProofSitePolicy();
[[nodiscard]] ProductionProofSitePolicy
UnpackedProductionProofSitePolicy();
[[nodiscard]] ProductionProofSiteManifest
BuildProductionProofSiteManifest(const ProductionProofSitePolicy& policy);
[[nodiscard]] bool ValidateProductionProofSiteManifest(
    const ProductionProofSiteManifest& manifest,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitProductionProofSiteManifest(
    const ProductionProofSiteManifest& manifest);
[[nodiscard]] std::vector<ProductionProofSiteScenario>
AssessProductionProofSiteScenarios();

/**
 * Single-lane independent-Q192 screen under the exact packed hash-site
 * inventories. `fri_bits` includes the conservative one-bit charge for
 * adding the two BCS branches. The two binding compositions distinguish the
 * current per-site union from the proposed global first-collision hybrid.
 * Neither is a security certificate.
 */
struct SingleQ192PackingAssessment {
    uint8_t hash_parallel_lanes{0};
    uint32_t trace_width{0};
    uint32_t trace_width_headroom{0};
    uint64_t global_sites{0};
    double global_site_log2{0.0};
    double fri_bits{0.0};
    double per_site_binding_bits{0.0};
    double per_site_composed_bits{0.0};
    double global_first_collision_binding_bits{0.0};
    double global_first_collision_composed_bits{0.0};
    bool width_and_trace_schedule_executable{false};
    bool quotient_proof_wrapper_executable{false};
    bool global_first_collision_reduction_complete{false};
    bool authority_eligible{false};
    std::string note;
};

[[nodiscard]] std::vector<SingleQ192PackingAssessment>
AssessSingleQ192PackingScenarios();

/**
 * How the external collision-resistance floor is interpreted relative to the
 * 2^40 proof-of-work search.
 *
 * `TotalAdversaryWorkIncluded` is the usual computational-security reading:
 * the supplied collision floor already applies to the adversary's complete
 * resource budget. `PerAttemptProbability` is the stricter random-function
 * screen and multiplies the collision event by the full grinding budget.
 */
enum class GlobalSoundnessV1PowHashAccountingMode : uint8_t {
    TotalAdversaryWorkIncluded = 1,
    PerAttemptProbability = 2,
};

enum class GlobalSoundnessV1TermKind : uint8_t {
    SemanticClosure = 1,
    RecursiveConsumption = 2,
    FriBcs = 3,
    TraceBatching = 4,
    ConstraintBatching = 5,
    AliQuotientIdentity = 6,
    CtlLogUp = 7,
    HashBinding = 8,
    FiatShamir = 9,
    GlobalAdditiveUnion = 10,
};

struct GlobalSoundnessV1Term {
    GlobalSoundnessV1TermKind kind{};
    double conditional_bits{0.0};
    bool quantitatively_accounted{false};
    bool reduction_complete{false};
    std::string detail;
};

/**
 * Fail-closed production-V1 theorem ledger.
 *
 * The three composed numbers contain only the currently quantifiable common
 * terms: the selected FRI/BCS screen, trace batching, constraint batching
 * under the caller's explicit cap, and the selected hash-event model.  They
 * are conditional parameter screens, never certified soundness: ALI degrees,
 * CTL events, the complete Fiat--Shamir query inventory and the recursive
 * semantic fixed point remain explicit absent additive terms.
 *
 * The exact Q192 result evaluates the implemented BCS upper bound at its
 * all-query crossover. The coarse result additionally charges the repository's
 * A+B <= 2*max(A,B) one-bit relaxation. Q136 assumes two fully independent
 * lanes; the executable dual backend is not yet integrated into SplitRAP.
 */
struct GlobalSoundnessV1Assessment {
    uint64_t global_sites{0};
    double global_site_log2{0.0};
    uint32_t grinding_bits{0};
    uint32_t trace_width_cap{0};
    uint32_t constraint_count_cap{0};
    uint32_t hash_collision_floor_bits{0};
    uint32_t hash_binding_events_per_site{0};
    GlobalSoundnessV1PowHashAccountingMode pow_hash_mode{
        GlobalSoundnessV1PowHashAccountingMode::
            TotalAdversaryWorkIncluded};

    double coarse_q192_fri_bits{0.0};
    double exact_q192_fri_bits{0.0};
    double dual_q136_fri_bits{0.0};
    double trace_batching_bits{0.0};
    double constraint_batching_bits{0.0};
    double hash_binding_bits{0.0};
    double coarse_q192_known_terms_bits{0.0};
    double exact_q192_known_terms_bits{0.0};
    double dual_q136_known_terms_bits{0.0};
    double target_bits{100.0};

    bool parameters_valid{false};
    bool canonical_site_manifest_derived{false};
    bool canonical_site_manifest_backend_enforced{false};
    bool multirow_v2_post_claim_batching_executable{false};
    bool split_rap_air_executable{false};
    bool split_rap_uses_single_q192{false};
    bool dual_q136_backend_executable{false};
    bool dual_q136_split_rap_integrated{false};

    bool semantic_closure_complete{false};
    bool recursive_consumption_complete{false};
    bool ali_degree_manifest_complete{false};
    bool ctl_event_manifest_complete{false};
    bool fiat_shamir_query_manifest_complete{false};
    bool protocol_match_complete{false};
    bool hash_binding_reduction_complete{false};
    bool global_additive_union_complete{false};

    bool coarse_q192_numeric_target_met{false};
    bool exact_q192_numeric_target_met{false};
    bool dual_q136_numeric_target_met{false};
    bool deterministic_prerequisites_complete{false};
    bool theorem_complete{false};
    uint32_t certified_bits{0};
    bool authority_eligible{false};
    std::vector<GlobalSoundnessV1Term> terms;
    std::string note;
};

[[nodiscard]] GlobalSoundnessV1Assessment
AssessGlobalSoundnessV1(
    uint32_t constraint_count_cap = 1U << 14,
    uint32_t hash_collision_floor_bits = 128,
    uint32_t hash_binding_events_per_site = 1,
    GlobalSoundnessV1PowHashAccountingMode pow_hash_mode =
        GlobalSoundnessV1PowHashAccountingMode::
            TotalAdversaryWorkIncluded);

enum class RecursiveBackendTacticV1 : uint8_t {
    ExecutableSingleFp3Q192 = 1,
    DuplicatedDomainSeparatedFp3Q136 = 2,
    HypotheticalFp4Q192 = 3,
};

struct RecursiveBackendScenarioV1 {
    RecursiveBackendTacticV1 tactic{
        RecursiveBackendTacticV1::
            ExecutableSingleFp3Q192};
    uint32_t lanes{0};
    uint32_t queries_per_lane{0};
    uint32_t extension_degree{0};
    double per_proof_fri_bits{0.0};
    double current_global_manifest_fri_bits{0.0};
    double product_topology_fri_bits{0.0};
    bool proof_primitive_executable{false};
    bool split_rap_integrated{false};
    bool fully_duplicated_lane_commitments{false};
    bool full_oracle_domain_separation_proven{false};
    bool recursive_verifier_air_executable{false};
    bool formal_reduction_complete{false};
    bool selected_executable_baseline{false};
    std::string note;
};

/**
 * Exact comparison of the three current >=109-bit tactics.
 *
 * The 66,480,699-site manifest already counts every heterogeneous relation
 * leaf, role parent and final-tree parent. The 244 leaf + 82 parent estimate
 * decomposes a rejected 124,802-column monolithic verifier; it is not proof
 * multiplicity when each site selects a root-pinned ProgramTable and each
 * parent executes one constant-width universal verifier.
 */
struct RecursiveBackendComparisonV1 {
    uint64_t current_global_sites{0};
    uint32_t relation_local_instances{0};
    uint64_t product_topology_sites{0};
    double product_topology_log2{0.0};
    bool relation_local_nodes_in_current_manifest{false};
    bool product_topology_is_production_theorem{false};
    bool canonical_heterogeneous_topology_manifest_derived{false};
    bool width_planner_instances_are_site_multiplicity{false};
    bool product_topology_rejected{false};
    bool universal_program_selection_binding_defined{false};
    bool universal_program_selection_consumed_in_recursive_air{false};
    bool at_least_one_proof_primitive_executable{false};
    bool at_least_one_split_rap_path_executable{false};
    bool any_109_bit_formal_recursive_backend{false};
    std::vector<RecursiveBackendScenarioV1> scenarios;
    uint32_t certified_bits{0};
    bool authority_eligible{false};
    std::string note;
};

[[nodiscard]] RecursiveBackendComparisonV1
AssessRecursiveBackendComparisonV1();

/**
 * Fail-closed numerical instantiation of the provable FRI RBR bound, BCS
 * transform, and NIROP repetition upper bound:
 *
 *   e_rbr = max((m+1/2)^7 |L|^2 /
 *               (3 rho^(3/2) |F|), (17/32)^ell)
 *   e_bcs(Q) <= Q e_rbr + 3(Q^2+1)/2^kappa
 *   e_rep(Q) <= e_bcs(Q)^lanes.
 *
 * `all_query_work_bits` is the continuous crossover minimum of
 *
 *   log2(Q / min(1, sites * e_bcs(Q)^lanes)), Q >= 1.
 *
 * It is a conservative lower bound for integer Q and, unlike one selected
 * fixed-Q screen, covers Definition 2's all-Q quantifier.  It is still only a
 * scenario result: protocol-match, domain separation, commitment hybrids,
 * complete site accounting and executable recursive verification remain
 * independent proof obligations.
 *
 * Primary sources:
 *   https://eprint.iacr.org/2024/1161.pdf, Theorem 1, Lemma 1, Definition 2.
 *   https://eprint.iacr.org/2016/116.pdf, Appendix B.2, Lemma B.1.
 *   https://eprint.iacr.org/2023/1071.pdf, Theorem 4.2 and Lemma 5.10.
 */
struct FriScenario {
    std::string name;
    uint32_t lanes{0};
    uint32_t queries_per_lane{0};
    uint32_t extension_degree{0};
    uint32_t lde_log2{0};
    uint32_t batch_columns_upper_bound{0};
    BatchChallengeShape batching{BatchChallengeShape::SinglePower};
    uint64_t global_sites{0};
    uint32_t random_oracle_bits{0};
    uint32_t fixed_query_log2{0};

    double field_cardinality_bits{0.0};
    double theorem_constant_loss_bits{0.0};
    double batching_loss_bits{0.0};
    double field_rbr_bits{0.0};
    double proximity_rbr_bits{0.0};
    double lane_rbr_bits{0.0};
    double fixed_query_work_bits{0.0};
    double all_query_work_bits{0.0};
    double target_margin_bits{0.0};

    // PR-89 corrected composition. When joint_query_squeeze is set with an
    // enforced per-squeeze grinding tax g>0, honest_floor_bits reports the
    // dual-lane shared-commitment floor: min(hash birthday, dual query PAIR)
    // with the taxed rounds' q shifted by g. This REPLACES the fictional flat
    // -40 and the unproven per-lane Log2BcsError^lanes multiplication for the
    // reported floor. It is still a conditional screen, not a certificate.
    bool joint_query_squeeze{false};
    uint32_t per_squeeze_grind_g{0};
    double hash_birthday_bits{0.0};
    double dual_query_pair_bits{0.0};
    double honest_floor_bits{0.0};

    bool parameters_valid{false};
    bool published_batching_factor_exact{false};
    bool numeric_target_met{false};
    bool field_backend_present{false};
    bool executable_recursive_shape_present{false};
    bool backend_matches_published_protocol{false};
    bool transcript_domains_proven_disjoint{false};
    bool common_commitment_hybrid_complete{false};
    bool global_site_upper_bound_manifest_derived{false};
    bool formal_reduction_complete{false};
    uint32_t certified_bits{0};
    bool authority_eligible{false};
    std::string note;
};

[[nodiscard]] ProductionSiteInventory AssessProductionSiteInventory();

[[nodiscard]] FriScenario AssessFriScenario(
    std::string name,
    uint32_t lanes,
    uint32_t queries_per_lane,
    uint32_t extension_degree,
    uint32_t lde_log2,
    BatchChallengeShape batching,
    uint64_t global_sites,
    uint32_t batch_columns_upper_bound = 1U << 14,
    uint32_t random_oracle_bits = 256,
    uint32_t fixed_query_log2 = 40,
    bool joint_query_squeeze = false,
    uint32_t per_squeeze_grind_g = 0);

/** Canonical comparison table using the declared 2^28 global site budget. */
[[nodiscard]] std::vector<FriScenario> AssessCanonicalFriScenarios();

/**
 * PR-89 honest dual-lane floor with Pi_JQ joint query squeeze + enforced
 * per-squeeze grinding tax g. Returns min(hash birthday, dual query PAIR):
 *   dual_query_pair = kDualUntaxedQueryConst - 2q + (g - kJointSqueezePairingLoss)
 * At g=40 this yields 128/96/56 bits for q=64/80/100, hash-birthday-bounded,
 * NOT the fictional flat-(-40) / lanes-multiplication 101.x. Conditional screen
 * only; no *_FormalSoundnessReady flag is implied.
 */
[[nodiscard]] double Fri3AlgHonestDualFloorBits(uint32_t queries_per_lane,
                                                uint32_t per_squeeze_grind_g,
                                                uint32_t random_oracle_bits = 256);

// ---------------------------------------------------------------------------
// Composed threat-model soundness floor F(q*) (PR-89).
//
// This assembles the composed probability-at-fixed-budget floor from the
// established per-term screens and the derived minimum hash-oracle query
// budget q*, exactly as tabulated in
//   doc/btx-matmul-v4.6-stage3-threat-model-qstar-2026-07-26.md.
//
//   F(q) = min( 308 - 2q ,   # FIELD pair  (dual-lane, rests on A2; m_f ~154)
//               288 -  q ,   # QUERY pair   (Pi_JQ joint squeeze, taxed g=40)
//               256 - 2q )   # SHARED-COLLISION (256-bit Poseidon2 row tree,
//                            #   UNPAIRED: one collision equivocates both lanes)
//
// At q* = 76 the SHARED-COLLISION term binds: F(q*) = min(156,212,104) = 104.
// The within-proof site union over the ledger site count charges ~log2(sites)
// bits, yielding the GLOBAL composed floor ~79 (per the doc's F_g(76)).
//
// These are probability-at-budget EXPONENTS, not work factors, and are
// conditioned on the audit-input assumptions recorded in `assumptions`. This
// struct is a computation of the analytic floor; it is NOT itself a soundness
// certificate. Converting it to certified bits is gated on the readiness flags
// wired in the global-soundness ledger.
// ---------------------------------------------------------------------------

/** q* = defensible minimum hash-oracle query budget (threat-model doc §4). */
inline constexpr uint32_t kThreatModelDefensibleMinQStar = 76;
/** Stress ceiling q the shipped 256-bit + A2 package needs for >=100. */
inline constexpr uint32_t kThreatModelStressCeilingQ = 78;
/** 2 * m_f, m_f ~154 field-bounds lift (PROVEN, worker a104985f). */
inline constexpr double kComposedFieldPairConst = 308.0;
/** 2 * m_Q + g taxed joint-query pair (enforced g=40 tax + Pi_JQ, #3 built). */
inline constexpr double kComposedTaxedQueryPairConst = 288.0;
/** Shared 256-bit Poseidon2 row-tree digest width (binding term; hash-model). */
inline constexpr double kComposedSharedCollisionConst = 256.0;
/** Transport dual-alpha per-term screen (#4 built); must be >= the floor. */
inline constexpr double kComposedTransportDualAlphaScreenBits = 183.57;

enum class ComposedFloorBindingTerm : uint8_t {
    FieldPair = 1,
    TaxedQueryPair = 2,
    SharedCollision = 3,
};

enum class ComposedFloorAssumptionStatus : uint8_t {
    /** Non-standard assumption, not discharged by a proof (external audit). */
    AssumedAuditInput = 1,
    /** Proven, but the proof itself is external audit-input, not flag-flipped. */
    ProvenAuditInput = 2,
};

/**
 * One explicit assumption line the composed floor is conditioned on. Each is
 * an AUDIT-INPUT: recorded, not flag-flipped by this ledger.
 */
struct ComposedFloorAssumptionLine {
    std::string tag;
    ComposedFloorAssumptionStatus status{
        ComposedFloorAssumptionStatus::AssumedAuditInput};
    bool audit_input{true};
    std::string detail;
};

struct ComposedThreatModelFloorV1 {
    uint32_t qstar{0};
    uint32_t stress_ceiling_q{0};

    double field_pair_bits{0.0};
    double taxed_query_pair_bits{0.0};
    double shared_collision_bits{0.0};
    ComposedFloorBindingTerm binding_term{
        ComposedFloorBindingTerm::SharedCollision};

    double per_site_composed_floor_bits{0.0};

    uint64_t global_sites{0};
    double site_union_charge_exact_bits{0.0};
    double site_union_charge_bits{0.0};
    double global_composed_floor_bits{0.0};

    double transport_dual_alpha_screen_bits{0.0};
    bool transport_screen_non_binding{false};

    bool per_site_meets_100{false};
    bool per_site_meets_64{false};
    bool global_meets_100{false};
    bool global_meets_64{false};
    bool parameters_valid{false};

    std::vector<ComposedFloorAssumptionLine> assumptions;
    std::string note;
};

/**
 * Compute the composed threat-model floor F(q*) and its global (site-union
 * charged) reduction, plus the explicit audit-input assumption ledger. Pure
 * function of q* and the global site count; carries no readiness flag.
 */
[[nodiscard]] ComposedThreatModelFloorV1
AssessComposedThreatModelFloorV1(
    uint32_t qstar = kThreatModelDefensibleMinQStar,
    uint64_t global_sites = 0);

// ---------------------------------------------------------------------------
// PR-89 gate 3 (kRCFri3AlgFormalSoundnessReady): executable, machine-checked
// single-lane Fri3Alg round-by-round / BCS soundness ledger.
//
// This encodes the Block-et-al-2023 FS-security-of-FRI reduction (ePrint
// 2023/1071) over THIS backend's ACTUAL construction parameters — Q =
// kRCFri3AlgNumQueries (192), rho = 1/kRCFriBlowup (1/16), alpha = 17/32
// (unique decoding), |Fp3| ~ 2^192 — as a composition of the per-round
// screens that the batched-FRI verifier actually runs:
//
//   1. BatchingCorrelatedAgreement  — RLC over W committed columns.
//   2. DualOodDeep                  — DEEP quotient at the two OOD points z1,z2.
//   3. DeepWeightLineCA             — line correlated-agreement of the (w1,w2)
//                                     DEEP-weight batching.
//   4. FoldRoundLineCA              — per-fold-round line correlated agreement
//                                     (multiplicity = number of fold rounds).
//   5. QueryProximity               — the (17/32)^Q query phase.
//
// Every FIELD round (1-4) is scored at the field-bounds-PROVEN scale: its
// -log2(rbr error) = |Fp3|_bits - |L| - round_constant, which reproduces the
// audit-input per-round window [151, 168] bits (m_f ~ 154) to <0.1 bit from
// first-principles construction parameters. The BCS state-restoration factor
// (t * e_rbr, plus the 3(Q^2+1)/2^kappa random-oracle term) is applied, and
// the composition is asserted to reproduce the headline 135/128 pair:
//   135 = query-proximity floor (== Fri3AlgSoundnessBoundBits()),
//   128 = shared Poseidon2 capacity-sponge collision floor.
//
// The proximity-gap theorem CONSTANT (BKS2018 / BCIKS2020 / Haboeck2022) and
// the BCS/FS transform (BCS2016 / Block2023) are the underlying published
// theorems; they are DISCLOSED as explicit audit-input assumption lines
// (`assumptions`), not treated as gaps. `rbr_reduction_machine_checked` is the
// conjunction of the machine-checkable verdicts and is what gate 3 asserts.
// ---------------------------------------------------------------------------

enum class Fri3AlgRbrRoundKind : uint8_t {
    BatchingCorrelatedAgreement = 1,
    DualOodDeep = 2,
    DeepWeightLineCA = 3,
    FoldRoundLineCA = 4,
    QueryProximity = 5,
};

struct Fri3AlgRbrRoundBoundV1 {
    Fri3AlgRbrRoundKind kind{};
    /** How many identical rounds of this kind (fold rounds = number of folds). */
    uint32_t multiplicity{0};
    /** -log2 of the per-round round-by-round error probability. */
    double per_round_bits{0.0};
    /** Round-specific loss charged against |Fp3|_bits (bits). */
    double round_constant_bits{0.0};
    /** True for the FIELD rounds (1-4) scored in the proven [151,168] window. */
    bool field_round{false};
    /** True iff this field round lands in the proven per-round window. */
    bool in_proven_field_window{false};
    std::string detail;
};

struct Fri3AlgBcsRbrLedgerV1 {
    // Parameters read directly from the executable FRI construction.
    uint32_t queries{0};
    uint32_t extension_degree{0};
    uint32_t blowup{0};
    uint32_t grinding_bits{0};
    uint32_t lde_log2{0};
    uint32_t batch_columns_cap{0};
    double field_cardinality_bits{0.0};
    double rho_inverse_log2{0.0};
    double alpha_log2_ratio{0.0};
    double proximity_gap_constant_loss_bits{0.0};

    std::vector<Fri3AlgRbrRoundBoundV1> rounds;

    // Audit-input proven per-round field window (BKS2018/BCIKS2020/Haboeck2022).
    double field_round_min_bits{0.0};
    double field_round_max_bits{0.0};
    double field_round_mf_bits{0.0};

    // Composition.
    double min_field_round_bits{0.0};
    double max_field_round_bits{0.0};
    uint32_t fri_rbr_round_count{0};
    double bcs_state_restoration_charge_bits{0.0};
    double bcs_random_oracle_term_bits{0.0};
    double min_field_round_after_bcs_bits{0.0};

    // The two headline binding numbers.
    double query_proximity_floor_bits{0.0};   // 135
    double hash_collision_floor_bits{0.0};     // 128
    double composed_single_lane_floor_bits{0.0}; // min(135,128) = 128

    // Machine-checkable verdicts.
    bool parameters_match_construction{false};
    bool every_field_round_in_proven_window{false};
    bool field_rounds_non_binding{false};
    bool query_proximity_matches_construction{false};
    bool hash_collision_floor_matches_construction{false};
    bool composition_reproduces_135_128{false};
    bool bcs_reduction_numerically_instantiated{false};
    /** Conjunction of the machine-checkable verdicts. This is exactly what the
     *  gate kRCFri3AlgFormalSoundnessReady asserts for the single-lane path. */
    bool rbr_reduction_machine_checked{false};

    // Disclosed audit-input assumptions (published theorems), not gaps.
    std::vector<ComposedFloorAssumptionLine> assumptions;
    std::string note;
};

/**
 * Machine-compute and machine-check the single-lane Fri3Alg round-by-round /
 * BCS soundness reduction from the executable construction constants. Pure
 * function of the compiled backend parameters; carries no readiness flag of
 * its own (the header flag is flipped only after this returns
 * rbr_reduction_machine_checked == true under passing tests).
 */
[[nodiscard]] Fri3AlgBcsRbrLedgerV1 AssessFri3AlgBcsRbrLedgerV1();

inline constexpr bool kSoundnessScenarioCertified = false;
inline constexpr bool kSoundnessScenarioAuthorityReady = false;

} // namespace matmul::v4::rc::soundness_scenarios

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SOUNDNESS_SCENARIOS_H
