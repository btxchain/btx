// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_AGGREGATION_SCHEDULE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_AGGREGATION_SCHEDULE_H

#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::aggregation_scheduler {

inline constexpr uint16_t kProductionAggregationScheduleVersion = 1;
inline constexpr uint8_t kProductionAggregationScheduleArity = 4;
inline constexpr uint16_t kBinaryV1AggregationScheduleVersion = 2;
inline constexpr uint8_t kBinaryV1AggregationScheduleArity = 2;

/**
 * One exact contiguous range in the global relation-leaf namespace.
 * `first_role_leaf` is the corresponding offset within the role's leaf
 * stream.  The canonical 28-family manifest determines these ranges without
 * enumerating any individual leaf.
 */
struct FamilyLeafRange {
    soundness_scenarios::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    uint32_t family_index{0};
    uint64_t first_leaf_site{0};
    uint64_t leaf_count{0};
    uint64_t first_role_leaf{0};

    bool operator==(const FamilyLeafRange&) const = default;
};

/**
 * One complete arity-four reduction level for a single role.  Both child and
 * parent site ranges are contiguous.  The last parent may have 1, 2 or 3
 * children when the previous level is not divisible by four.  Such a node is
 * still an explicitly charged proof site; it may not be silently elided.
 */
struct RoleAggregationLevel {
    uint32_t level{0};
    uint64_t first_child_site{0};
    uint64_t child_count{0};
    uint64_t first_parent_site{0};
    uint64_t parent_count{0};

    bool operator==(const RoleAggregationLevel&) const = default;
};

struct RoleAggregationPlan {
    RCStage3RelationRole role{};
    uint64_t first_leaf_site{0};
    uint64_t leaf_count{0};
    uint64_t root_site{0};
    std::vector<RoleAggregationLevel> levels;

    bool operator==(const RoleAggregationPlan&) const = default;
};

/**
 * Verifier-recomputable compact schedule for every below-root production
 * aggregation node.  The fixed normalized binary-16 tree is deliberately not
 * repeated here; its fifteen nodes remain committed by unified-root V3.
 */
struct ProductionAggregationSchedule {
    uint16_t version{kProductionAggregationScheduleVersion};
    uint8_t arity{kProductionAggregationScheduleArity};
    uint256 manifest_commitment{};
    uint64_t relation_leaf_sites{0};
    uint64_t below_root_parent_sites{0};
    uint64_t final_tree_parent_sites{0};
    uint64_t total_proof_sites{0};
    std::vector<FamilyLeafRange> families;
    std::vector<RoleAggregationPlan> roles;
    uint256 commitment{};

    bool operator==(const ProductionAggregationSchedule&) const = default;
};

[[nodiscard]] ProductionAggregationSchedule
BuildProductionAggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);

[[nodiscard]] uint256 CommitProductionAggregationSchedule(
    const ProductionAggregationSchedule& schedule);

[[nodiscard]] bool ValidateProductionAggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    std::string* why = nullptr);

/**
 * Canonical V1 fallback topology: reuse the exact selected production leaf
 * inventory but reduce every role with binary parents.  This intentionally
 * differs from the arity-four production candidate so the existing full-wide
 * normalized verifier can execute all six V_CS families at every node.
 *
 * It is a scenario/implementation path, not the active unified-root format.
 */
[[nodiscard]] ProductionAggregationSchedule
BuildBinaryV1AggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);
[[nodiscard]] uint256 CommitBinaryV1AggregationSchedule(
    const ProductionAggregationSchedule& schedule);
[[nodiscard]] bool ValidateBinaryV1AggregationSchedule(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    std::string* why = nullptr);

/**
 * One canonical parent job. `parent_ordinal` is zero-based over every
 * below-root parent, in role/level/index order.  `seed` binds the job to one
 * unified-root seed, the exact schedule, role, range, level, and global site.
 */
struct ParentWorkItem {
    uint64_t parent_ordinal{0};
    RCStage3RelationRole role{};
    uint32_t level{0};
    uint64_t parent_index{0};
    uint64_t parent_site{0};
    uint64_t first_child_site{0};
    uint8_t child_count{0};
    uint256 schedule_commitment{};
    uint256 seed{};

    bool operator==(const ParentWorkItem&) const = default;
};

[[nodiscard]] std::optional<ParentWorkItem>
ProductionAggregationParentWorkItem(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    std::string* why = nullptr);

[[nodiscard]] std::optional<ParentWorkItem>
BinaryV1AggregationParentWorkItem(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    std::string* why = nullptr);

struct BinaryV1SoundnessScenario {
    ProductionAggregationSchedule schedule;
    uint64_t exact_total_sites{0};
    uint64_t union_bound_cap{0};
    uint32_t union_bound_log2{0};
    soundness_scenarios::FriScenario exact_site_screen;
    soundness_scenarios::FriScenario cap_screen;
    bool every_parent_child_count_at_most_two{false};
    /** False: the wide V_CS is not a shape fixed point and its Q128 full-row
     * openings exceed the 16 MiB per-lane codec cap. */
    bool every_parent_full_wide_eligible{false};
    bool numeric_exact_site_target_met{false};
    bool numeric_cap_target_met{false};
    bool all_node_execution_complete{false};
    bool theorem_complete{false};
    bool authority_eligible{false};
    std::string note;
};

/** Recompute the binary site count and dual-Q128 independent-batching screen. */
[[nodiscard]] BinaryV1SoundnessScenario
AssessBinaryV1SoundnessScenario(
    const soundness_scenarios::ProductionProofSiteManifest& manifest);

/**
 * A callback cannot return an unbound opaque commitment.  It must echo the
 * canonical work seed and bind its produced parent through
 * CommitProductionAggregationReceipt.  This is structural scheduling, not a
 * recursive child-proof verifier.
 */
struct ParentReceipt {
    uint256 work_seed{};
    uint256 parent_commitment{};
    uint256 binding{};

    bool operator==(const ParentReceipt&) const = default;
};

[[nodiscard]] uint256 CommitProductionAggregationReceipt(
    const ParentWorkItem& work,
    const uint256& parent_commitment);

using ParentCallback =
    std::function<std::optional<ParentReceipt>(const ParentWorkItem& work,
                                               std::string* why)>;

/**
 * Hash-chained paging cursor. BeginProductionAggregationExecution is the only
 * canonical start.  Passing each returned cursor into the next call processes
 * a contiguous prefix without storing per-node receipts.
 */
struct ExecutionCursor {
    uint256 schedule_commitment{};
    uint256 unified_root_seed{};
    uint64_t next_parent_ordinal{0};
    uint256 receipt_chain{};
    uint256 cursor_binding{};
    bool complete{false};

    bool operator==(const ExecutionCursor&) const = default;
};

[[nodiscard]] ExecutionCursor BeginProductionAggregationExecution(
    const ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed);

[[nodiscard]] bool ExecuteProductionAggregationPage(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const ProductionAggregationSchedule& schedule,
    const ParentCallback& callback,
    uint64_t max_parents,
    ExecutionCursor& cursor,
    std::string* why = nullptr);

// ===========================================================================
// Cryptographic child consumption.
//
// Everything above this line is the STRUCTURAL scheduler: it decides which
// parent jobs exist and binds their receipts into a hash chain, but it never
// looks at a proof.  Everything below is the layer that makes a
// `ParentCallback` genuinely consume REAL child proofs:
//
//   1. every child proof is independently re-verified by the REAL unmodified
//      air_quotient::AirQuotientVerify<Fp3, AirFriBackendAlg<Fp3>> against the
//      child constraint system under the child Fiat-Shamir seed;
//   2. the four accepted proofs are then consumed IN-AIR by
//      recursive_parent_air::BuildFourSlotSelfSimilarCtlParentV1, whose parent
//      V_CS checks the children's Merkle / fold / DEEP / quotient equations in
//      constraint and derives the parent statement h_nu as the in-circuit
//      AlgHash of the four children's FULL public-IO tuples;
//   3. the receipt's parent_commitment is a domain-separated hash of the work
//      item AND h_nu, so it is unforgeable without the four child proofs.
//
// This is NOT sound recursion yet.  See
// kProductionAggregationCryptographicChildConsumptionReady below.
// ===========================================================================

/** The exact child-proof type the in-parent V_CS verifier consumes. */
using ChildProof =
    recursive_parent_air::FourSlotSelfSimilarCtlParentV1::ChildProof;
using ChildConstraintSystem =
    air_quotient::AirConstraintSystem<gkr_field::Fp3>;

/**
 * The real child proofs for ONE parent job.
 *
 * SHAPE CONSTRAINT (inherited from the four-slot self-similar primitive, not
 * introduced here): one arity-4 parent verifies four proofs of ONE identical
 * child constraint system under ONE Fiat-Shamir seed.  `child_cs` is therefore
 * per-node, not per-slot; distinct nodes may carry distinct real roles.
 */
struct ParentChildProofBundle {
    ChildConstraintSystem child_cs;
    std::array<ChildProof, kProductionAggregationScheduleArity> child_proofs;
    uint256 child_fs_seed{};
};

/**
 * Supplies the real child proofs for one parent job.  Returning false (or a
 * bundle that fails verification) makes the parent callback fail closed, which
 * aborts the whole aggregation page — a rejected child proof cannot be
 * scheduled around.
 */
using ChildProofSource =
    std::function<bool(const ParentWorkItem& work,
                       ParentChildProofBundle& out,
                       std::string* why)>;

/**
 * Verifier-recomputable node context for one parent job.  Nothing here is
 * prover-chosen: level/index come from the schedule, the public lanes are
 * derived from the schedule commitment and the unified-root seed, and the
 * node's own receipt-root lanes are derived from its global proof site.  Two
 * different sites therefore yield different parent statements over the same
 * four children (cross-site replay is not free).
 */
[[nodiscard]] recursive_parent_air::FourSlotNodeContextV1
CanonicalParentNodeContext(const ParentWorkItem& work);

/** Canonical uint256 packing of the in-circuit parent statement h_nu. */
[[nodiscard]] uint256 PackParentStatement(
    const alg_hash::Digest& statement);

/** parent_commitment = H(domain || work item || h_nu). */
[[nodiscard]] uint256 CommitConsumedParentStatement(
    const ParentWorkItem& work, const uint256& parent_statement);

/** Exact record of one node's cryptographic child consumption. */
struct CryptographicChildConsumption {
    uint64_t parent_ordinal{0};
    uint64_t parent_site{0};
    uint32_t level{0};
    uint64_t parent_index{0};
    uint8_t child_count{0};

    // Stage 1 — standalone proof-level verification (real unmodified verifier).
    uint8_t children_standalone_verified{0};
    bool all_children_standalone_verified{false};
    std::string child_verify_reject_reason;

    // Stage 2 — in-AIR consumption by the arity-4 parent V_CS.
    bool all_children_verified_in_parent_air{false};
    bool terminal_lanes_sourced_from_in_parent_verifier{false};
    bool four_child_roots_sourced_from_verifier_outputs{false};
    bool parent_statement_equals_child_aggregation{false};
    bool self_similar_arity4_shape{false};
    uint32_t witness_violations{0};
    uint32_t parent_rows{0};
    uint32_t parent_columns{0};
    uint32_t vcs_columns{0};

    uint256 parent_statement{};
    uint256 parent_commitment{};

    /**
     * GAP[8] ChildFiatShamirReplayNotClosed.  False by construction: the child
     * Fiat-Shamir transcript is supplied by seed rather than replayed from a
     * proof-independent role seed by an in-parent SHA chip.  Until that lane
     * lands, in-AIR child verification is executable but not sound recursion,
     * so `recursion_soundness_admissible` stays false and no consumption may be
     * treated as consensus authority.
     */
    bool child_fiat_shamir_replayed_in_parent{false};
    bool recursion_soundness_admissible{false};

    bool valid{false};
    std::string note;
};

/**
 * Run both stages for one parent job.  `valid` is true only when every child
 * proof standalone-verified, the parent V_CS built with zero witness
 * violations, all four children verified in-AIR, the terminal root lanes were
 * sourced from the in-parent verifier's own cells, and the parent statement
 * equals the in-circuit aggregation of the four child statements.
 */
[[nodiscard]] CryptographicChildConsumption
ConsumeRealChildProofsForParent(const ParentWorkItem& work,
                                const ParentChildProofBundle& bundle);

/**
 * A ParentCallback that genuinely consumes real child proofs.  The receipt it
 * returns is bound to h_nu, so `ExecuteProductionAggregationPage` driven with
 * this callback is a cryptographic aggregation walk rather than a structural
 * one.  A failing consumption returns nullopt and the page fails closed.
 *
 * `trace`, when non-null, receives one record per consumed node in order.
 */
[[nodiscard]] ParentCallback
MakeCryptographicChildConsumingParentCallback(
    const ChildProofSource& source,
    std::vector<CryptographicChildConsumption>* trace = nullptr);

/**
 * This flag means exact manifest ranges and parent jobs are executable and
 * root-bindable.  It deliberately does not mean that the callback verifies a
 * recursive child proof.
 */
inline constexpr bool
    kProductionAggregationStructuralSchedulerExecutable = true;

/**
 * TRUE: a ParentCallback built by
 * MakeCryptographicChildConsumingParentCallback loads four REAL child FRI
 * proofs, re-verifies each with the real unmodified AirQuotientVerify,
 * consumes all four in-AIR through the arity-4 parent V_CS, and returns a
 * commitment bound to the in-circuit parent statement.  No work-item hash is
 * involved.  This is the MECHANISM flag: proofs are genuinely consumed.
 */
inline constexpr bool
    kProductionAggregationRealChildProofConsumptionExecutable = true;

/**
 * FALSE, and it must stay false until GAP[8] closes.
 *
 * "Cryptographically ready" would mean a parent's acceptance of its children is
 * a SOUND recursive verification.  It is not: the in-parent V_CS consumes the
 * children's Fiat-Shamir scalars as pinned inputs instead of replaying the
 * child transcript from a proof-independent role seed (matmul_v4_rc_stage3_
 * recursive.cpp `child_fiat_shamir_replay_closed`, surfaced as
 * RCStage3RecursiveGapCode::ChildFiatShamirReplayNotClosed).  A prover free to
 * choose the child challenges is not bound by the in-AIR FRI equations, so
 * `CryptographicChildConsumption::recursion_soundness_admissible` is false for
 * every node regardless of how honest the children are.
 *
 * Consequence for the tree: the mechanism above is executable at every node,
 * but no aggregation root it produces carries soundness.
 */
inline constexpr bool
    kProductionAggregationCryptographicChildConsumptionReady = false;
inline constexpr bool kBinaryV1ScheduleScenarioExecutable = true;
inline constexpr bool kBinaryV1AllNodeExecutionComplete = false;

static_assert(kProductionAggregationStructuralSchedulerExecutable);
static_assert(kProductionAggregationRealChildProofConsumptionExecutable);
static_assert(!kProductionAggregationCryptographicChildConsumptionReady);
static_assert(kBinaryV1ScheduleScenarioExecutable);
static_assert(!kBinaryV1AllNodeExecutionComplete);

} // namespace matmul::v4::rc::aggregation_scheduler

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_AGGREGATION_SCHEDULE_H
