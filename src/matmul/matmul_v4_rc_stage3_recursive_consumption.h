// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_CONSUMPTION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_CONSUMPTION_H

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>
#include <matmul/matmul_v4_rc_stage3_v6_fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_consumption {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace scheduler = aggregation_scheduler;
namespace v6 = stage3_v6_fs;

inline constexpr uint16_t kRecursiveConsumptionVersion = 1;

using V6BindingProof =
    aq::AirQuotientProof<gkr_field::Fp3,
                         aq::AirFriBackendAlg<gkr_field::Fp3>>;

/**
 * Executable bounded bridge from one exact production-scheduler work item to
 * real proof objects:
 *
 *  - source_children are re-verified as dual-Q128/V5 AIR proofs;
 *  - their exact finite V5 transcripts are replayed;
 *  - normalized_parent is verified against the proof-derived lane inputs and
 *    the exact scheduler work seed;
 *  - v6_binding_proof proves the algebraic transcript over those derived
 *    child outputs; and
 *  - receipt is the scheduler's canonical seed-bound receipt.
 *
 * The carrier deliberately contains the source proofs, not merely host report
 * bits or opaque child commitments.  This is an executable integration seam,
 * not a production recursive authority: the selected bounded parent omits
 * expensive V_CS families. The separate V5/V6 composition now publishes the
 * eight row-root cells from native same-trace V5 outputs, but this artifact
 * does not consume that composition and the other full-transcript/Fiat-Shamir
 * cells remain unmapped.
 */
struct RecursiveParentArtifact {
    uint16_t version{kRecursiveConsumptionVersion};
    scheduler::ParentWorkItem claimed_work{};
    uint256 child_fs_seed{};
    std::vector<ar::DualAlgAirProof> source_children;
    ar::DualAlgAirProof normalized_parent;
    V6BindingProof v6_binding_proof;
    scheduler::ParentReceipt receipt{};

    uint64_t parent_prove_micros{0};
    uint64_t normalized_parent_verify_micros{0};
    uint64_t v6_prove_micros{0};
    uint64_t v6_verify_micros{0};
    uint64_t verify_micros{0};
    uint32_t normalized_parent_rows{0};
    uint32_t normalized_parent_columns{0};
    uint32_t normalized_parent_constraints{0};
    uint32_t v6_rows{0};
    uint32_t v6_columns{0};
    uint32_t v6_constraints{0};
    uint64_t normalized_parent_batch_bytes{0};
    uint64_t v6_batch_bytes{0};
    /** True iff every normalized V_CS family was present in the proved
     * parent.  This is derived from the canonical work item, never selected
     * by the prover. */
    bool full_vcs_families{false};
    bool valid{false};
    std::string note;
};

/**
 * Exact lower-bound screen for the existing wide normalized verifier.  The
 * parent proof opens a complete row at every query, so the row-value payload
 * alone is:
 *
 *   Q * (parent_columns + quotient) * 3 * sizeof(uint64_t)
 *
 * per V5 lane, before Merkle paths, folds or framing.  This preflight runs the
 * real child verification/witness builder but deliberately stops before the
 * prohibitively expensive parent commitment.
 */
struct FullWideVcsPreflight {
    uint32_t logical_children{0};
    uint32_t normalized_lanes{0};
    uint32_t parent_rows{0};
    uint32_t parent_columns{0};
    uint32_t parent_constraints{0};
    uint64_t minimum_query_value_bytes_per_lane{0};
    uint64_t codec_bytes_per_lane{0};
    bool backend_columns_supported{false};
    bool proof_codec_supported{false};
    bool self_similar_shape{false};
    bool executable{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] FullWideVcsPreflight AssessFullWideVcsPreflight(
    const aq::AirConstraintSystem<gkr_field::Fp3>& child_cs,
    const std::vector<ar::DualAlgAirProof>& source_children,
    const uint256& child_fs_seed);

/**
 * Build one bounded receipt for a canonical production-schedule ordinal.
 * source_children.size() must equal the work item's exact child_count.
 */
[[nodiscard]] RecursiveParentArtifact BuildRecursiveParentArtifact(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    uint64_t parent_ordinal,
    const aq::AirConstraintSystem<gkr_field::Fp3>& child_cs,
    const std::vector<ar::DualAlgAirProof>& source_children,
    const uint256& child_fs_seed);

/**
 * Recompute the exact work item and re-run every proof verification.  The
 * caller supplies the child relation AIR; no process-local "accepted" bit is
 * trusted.
 */
[[nodiscard]] bool VerifyRecursiveParentArtifact(
    const soundness_scenarios::ProductionProofSiteManifest& manifest,
    const scheduler::ProductionAggregationSchedule& schedule,
    const uint256& unified_root_seed,
    const aq::AirConstraintSystem<gkr_field::Fp3>& child_cs,
    const RecursiveParentArtifact& artifact,
    std::string* why = nullptr,
    uint64_t* verify_micros = nullptr);

/** The bounded proof-to-receipt adapter executes and is mutation tested. */
inline constexpr bool kBoundedProofAwareReceiptExecutable = true;
/**
 * The existing wide normalized verifier can execute every V_CS family for at
 * most two logical dual-V5 children under the 16,384-column backend cap.
 * Canonical arity-four jobs remain on the binding-only profile until the
 * vertical fixed-point verifier replaces the wide unrolling.
 */
inline constexpr uint32_t kFullWideLogicalChildCap = 2;
inline constexpr bool kFullWideCodecPreflightExecutable = true;
inline constexpr bool kFullWideVcsChildConsumptionExecutable = false;
/** Full V_CS execution and full-transcript V5->V6 ownership are still open. */
inline constexpr bool kProductionRecursiveChildConsumptionReady = false;
inline constexpr bool kRecursiveConsumptionConsensusAuthority = false;

static_assert(kBoundedProofAwareReceiptExecutable);
static_assert(kFullWideCodecPreflightExecutable);
static_assert(!kFullWideVcsChildConsumptionExecutable);
static_assert(!kProductionRecursiveChildConsumptionReady);
static_assert(!kRecursiveConsumptionConsensusAuthority);

} // namespace matmul::v4::rc::recursive_consumption

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_CONSUMPTION_H
