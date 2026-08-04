// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFY_COST_MODEL_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFY_COST_MODEL_H

#include <cstdint>

// ============================================================================
// ANALYTIC verify-time model for the single normalized-root Stage-3 verify
// (RCStage3RecursiveGapCode::ProductionPerformanceUnmeasured, gap code 10).
//
// This header closes the MODEL half of the gap: it pins, as constexpr
// arithmetic over the frozen protocol shape, the exact operation counts a
// relay verifier executes for one RCStage3UnifiedRootPublicPin, and projects
// wall time against the 900 ms relay budget under three explicit hardware
// envelopes. The gap itself stays open until a measured run replaces the
// envelopes (kRCStage3ProductionVerifyPerformanceMeasured below stays false).
//
// SHAPE INPUTS (all mirrored from frozen source, cited per constant):
//   - Dual-lane alg FRI: 2 lanes x Q=128 queries, blowup 16, g=40
//     (matmul_v4_rc_fri_ext3_alg.h: kRCFri3AlgDualNumLanes/QueriesPerLane).
//   - Selected V1 normalized parent: W = 2,184 columns, fully-quadratic x^7,
//     four physical verifier lanes, recursive LDE 2^24 => n_coeffs = 2^20
//     (matmul_v4_rc_stage3_recursive_fixedpoint.h SelectCompleteFixedPointV1,
//      narrow_recurse.h lde_log2{24}).
//   - Production episode leaf child: W = 26, N = 2^16, LDE 2^20, depth 20,
//     16 folds (matmul_v4_rc_stage3_narrow_recurse.cpp
//      ProductionEpisodeChildShape).
//   - Per query the hash-opening program executes THREE sponge programs —
//     current full row (W+1 Fp3 openings), shifted full row (W+1), trace-only
//     row (W) — each with a Merkle path of depth log2(LDE), plus one even/odd
//     opening per fold layer (matmul_v4_rc_stage3_recursive_fixedpoint.cpp
//      BuildHashOpeningProgram).
//   - Row-leaf sponge cost: ceil((3*(W+1)+1)/8) AlgHash permutations
//     (matmul_v4_rc_stage3_narrow_recurse.cpp RowLeafPermutationRows;
//      alg_hash rate 8).
//   - AlgHash = Poseidon2-Goldilocks t=12, 118 S-boxes, ~750 Fp mul +
//     ~1000 Fp add per permutation (matmul_v4_rc_alg_hash.h).
//
// MEASURED ANCHORS (taken as given from the existing R&D runs):
//   - bytecode composition/OOD constraint evaluation: 0.7–1.4 ms per case;
//   - universal-topology screen: ~65 ms per case;
//   - proving (not modeled here): ~41 s.
//
// HEADLINE RESULT (derivation in the constexpr functions below):
//   Single normalized-root verify, single CPU thread:
//     optimistic   ~368 ms   (vectorized Poseidon2 0.30 us/perm, SHA-NI)
//     nominal      ~575 ms   (scalar Poseidon2 0.50 us/perm)
//     conservative ~1,062 ms (unvectorized 1.00 us/perm, no SHA-NI)
//   => 900 ms HOLDS on a modern desktop CPU at nominal (64% of budget) but
//   the conservative tail breaches by ~18%. Margin is restored WITHOUT any
//   GPU/datacenter accel by either of two ordinary-CPU levers:
//     (a) query-parallel verify (the 256 queries are independent): 4 cores
//         gives nominal ~273 ms and even conservative ~478 ms;
//     (b) 4-lane AVX2 Poseidon2 (~0.15 us/perm): total ~330–400 ms.
//   DOMINANT COST: AlgHash row-leaf sponge recomputation of the full opened
//   2,184-column parent rows — 630k of ~722k permutations (~87% of hash
//   work, 55–70% of end-to-end verify). It scales as
//         Q_total * 3 * ceil((3(W+1)+1)/8),
//   i.e. parent WIDTH W is the verify-time lever, not query count Q.
//   Composition (1.4 ms) and topology (65 ms) are NOT the bottleneck.
//
//   NEGATIVE RESULT (architecture-forcing): natively verifying the arity-4
//   tree of 341 node proofs (256 leaves + 64 + 16 + 4 + 1) instead of one
//   normalized root costs ~256 x 30 ms + 85 x 410 ms ~= 42.6 s — over budget
//   by ~47x. There is NO native-fallback relay path; the 900 ms budget is
//   reachable ONLY through the single-root recursion, so closing gap 10
//   remains conditional on closing SelfSimilarFixedPointNotClosed (gap 9).
// ============================================================================

namespace matmul::v4::rc::verify_cost_model {

// ---------------------------------------------------------------------------
// Frozen shape constants (mirrors; static_asserts in the .cpp/test must pin
// these against the authoritative headers so drift fails the build).
// ---------------------------------------------------------------------------
inline constexpr uint32_t kDualLanes = 2;              // kRCFri3AlgDualNumLanes
inline constexpr uint32_t kQueriesPerLane = 128;       // kRCFri3AlgDualQueriesPerLane
inline constexpr uint32_t kTotalQueries = kDualLanes * kQueriesPerLane; // 256
inline constexpr uint32_t kBlowup = 16;                // kRCFriBlowup
inline constexpr uint32_t kGrindingBits = 40;          // kRCFriGrindingBits
inline constexpr uint32_t kAlgHashRate = 8;            // alg_hash::kAlgHashRate

// Selected V1 normalized parent (SelectCompleteFixedPointV1).
inline constexpr uint32_t kParentW = 2184;
inline constexpr uint32_t kParentFolds = 20;           // log2(n_coeffs) = 20
inline constexpr uint32_t kParentMerkleDepth = 24;     // log2(LDE 2^24)

// Production episode leaf child (ProductionEpisodeChildShape).
inline constexpr uint32_t kLeafW = 26;
inline constexpr uint32_t kLeafFolds = 16;             // log2(2^16)
inline constexpr uint32_t kLeafMerkleDepth = 20;       // log2(2^20)
inline constexpr uint32_t kLeafQueries = 192;          // kRCFri3AlgNumQueries

// Arity-4 site tree modeled for the native-fallback bound.
inline constexpr uint32_t kTreeLeaves = 256;
inline constexpr uint32_t kTreeInternal = 64 + 16 + 4 + 1; // 85
inline constexpr uint32_t kTreeNodes = kTreeLeaves + kTreeInternal; // 341

// Relay budget.
inline constexpr uint64_t kRelayBudgetMicros = 900'000;

// Measured anchors (microseconds), taken as given from R&D runs.
inline constexpr uint64_t kMeasuredCompositionMicrosLo = 700;
inline constexpr uint64_t kMeasuredCompositionMicrosHi = 1'400;
inline constexpr uint64_t kMeasuredTopologyScreenMicros = 65'000;

// ---------------------------------------------------------------------------
// Permutation accounting (exact, from BuildHashOpeningProgram).
// ---------------------------------------------------------------------------

/** Sponge permutations to hash one opened row of `w` Fp3 openings:
 *  stream = 3*w + 1 Fp words (RowLeafPermutationRows). */
[[nodiscard]] constexpr uint64_t RowSpongePerms(uint64_t w)
{
    return (3 * w + 1) / kAlgHashRate + 1;
}

/** AlgHash permutations executed per FRI query for one node of width W,
 *  Merkle depth D (= log2 LDE) and F fold layers:
 *    current full row (W+1) + shifted full row (W+1) + trace row (W),
 *    three depth-D authentication paths (1 perm per 2->1 compress),
 *    per fold layer j: 1 leaf-pair perm + a depth-(D-1-j) path. */
[[nodiscard]] constexpr uint64_t PermsPerQuery(uint64_t w, uint64_t depth,
                                               uint64_t folds)
{
    uint64_t perms = RowSpongePerms(w + 1) * 2 + RowSpongePerms(w);
    perms += 3 * depth;
    for (uint64_t j = 0; j < folds; ++j) {
        perms += 1 + (depth - 1 - j);
    }
    return perms;
}

/** Whole-proof permutation count for one node verify at Q total queries. */
[[nodiscard]] constexpr uint64_t PermsPerNode(uint64_t w, uint64_t depth,
                                              uint64_t folds, uint64_t queries)
{
    return queries * PermsPerQuery(w, depth, folds);
}

// Evaluated shape facts (pinned):
//   parent: 820*2 + 820 rows + 72 paths + 290 folds = 2,822 perms/query;
//           x 256 queries = 722,432 perms per root verify, of which
//           row sponges are 629,760 (~87%).
//   leaf:   ~293 perms/query; x 192 queries = ~56k perms per leaf verify.
static_assert(PermsPerQuery(kParentW, kParentMerkleDepth, kParentFolds) == 2822);
static_assert(PermsPerNode(kParentW, kParentMerkleDepth, kParentFolds,
                           kTotalQueries) == 722'432);
static_assert(kTotalQueries * (RowSpongePerms(kParentW + 1) * 2 +
                               RowSpongePerms(kParentW)) == 629'760);

// ---------------------------------------------------------------------------
// Fp3 algebra accounting (RLC composition U, dual-OOD DEEP, per-point
// quotient). Per query: ~W Fp3 mul-adds per opened full row for U(x), two
// rows, doubled for the two DEEP points => ~4W; +O(folds) for fold checks.
// ---------------------------------------------------------------------------
[[nodiscard]] constexpr uint64_t Fp3MulsPerNode(uint64_t w, uint64_t folds,
                                                uint64_t queries)
{
    return queries * (4 * w + 8 * folds);
}

// ---------------------------------------------------------------------------
// Hardware envelope. All times in nanoseconds unless stated.
// ---------------------------------------------------------------------------
struct CostEnvelope {
    // Poseidon2-GL t=12 permutation (118 S-boxes ~= 750 Fp mul + 1000 add).
    uint64_t perm_ns;
    // Fp3 (degree-3 Goldilocks tower) multiply: 9 Fp muls + adds.
    uint64_t fp3_mul_ns;
    // SHA256d Fiat-Shamir replay over serialized proof bytes, in MB/s.
    uint64_t sha_mb_per_s;
    // Native CTL AIR verify per role proof (narrow SHA-path, 14 roles).
    uint64_t ctl_per_role_us;
    // Composition/OOD bytecode evaluation per case (measured anchor).
    uint64_t composition_us;
    // Misc: statement/manifest/schedule commitment recompute + deserialize.
    uint64_t misc_us;
};

inline constexpr CostEnvelope kOptimistic{300, 12, 2000, 2'000, 700, 8'000};
inline constexpr CostEnvelope kNominal{500, 18, 1000, 3'500, 1'400, 12'000};
inline constexpr CostEnvelope kConservative{1'000, 25, 400, 6'000, 1'400, 20'000};

/** Serialized dual-lane root proof bytes: per query, 2 full rows (W+1) +
 *  trace row (W) of Fp3 (24 B) + fold openings + paths (32 B digests). */
[[nodiscard]] constexpr uint64_t RootProofBytes(uint64_t w, uint64_t depth,
                                                uint64_t folds, uint64_t queries)
{
    const uint64_t row_bytes = (2 * (w + 1) + w) * 24;
    const uint64_t path_bytes = (3 * depth + folds * depth) * 32;
    const uint64_t fold_bytes = folds * 2 * 24;
    return queries * (row_bytes + path_bytes + fold_bytes);
}

struct VerifyProjection {
    uint64_t hash_us;        // AlgHash permutations (dominant)
    uint64_t algebra_us;     // Fp3 RLC/DEEP/quotient
    uint64_t composition_us; // measured anchor
    uint64_t fs_sha_us;      // SHA256d transcript replay
    uint64_t topology_us;    // measured anchor (~65 ms)
    uint64_t ctl_us;         // 14 native CTL AIR proofs + dual-alpha terminal
    uint64_t misc_us;
    uint64_t total_us;
    bool within_relay_budget;
};

/** Single normalized-root relay verify (Model A: recursion closed). */
[[nodiscard]] constexpr VerifyProjection
ProjectSingleRootVerify(const CostEnvelope& e, uint32_t threads = 1)
{
    VerifyProjection p{};
    const uint64_t perms =
        PermsPerNode(kParentW, kParentMerkleDepth, kParentFolds, kTotalQueries);
    // Queries are independent; hash + algebra parallelize near-linearly.
    p.hash_us = perms * e.perm_ns / 1000 / threads;
    p.algebra_us = Fp3MulsPerNode(kParentW, kParentFolds, kTotalQueries) *
                   e.fp3_mul_ns / 1000 / threads;
    p.composition_us = e.composition_us;
    p.fs_sha_us = RootProofBytes(kParentW, kParentMerkleDepth, kParentFolds,
                                 kTotalQueries) /
                  e.sha_mb_per_s; // bytes / (MB/s) == us
    p.topology_us = kMeasuredTopologyScreenMicros;
    p.ctl_us = 14 * e.ctl_per_role_us;
    p.misc_us = e.misc_us;
    p.total_us = p.hash_us + p.algebra_us + p.composition_us + p.fs_sha_us +
                 p.topology_us + p.ctl_us + p.misc_us;
    p.within_relay_budget = p.total_us <= kRelayBudgetMicros;
    return p;
}

/** Native-fallback bound (Model B: verify all 341 node proofs directly). */
[[nodiscard]] constexpr uint64_t ProjectNativeTreeVerifyMicros(const CostEnvelope& e)
{
    const uint64_t leaf_us =
        PermsPerNode(kLeafW, kLeafMerkleDepth, kLeafFolds, kLeafQueries) *
            e.perm_ns / 1000 +
        Fp3MulsPerNode(kLeafW, kLeafFolds, kLeafQueries) * e.fp3_mul_ns / 1000 +
        e.composition_us;
    const uint64_t parent_us = ProjectSingleRootVerify(e).hash_us +
                               ProjectSingleRootVerify(e).algebra_us +
                               e.composition_us;
    return kTreeLeaves * leaf_us + kTreeInternal * parent_us +
           kMeasuredTopologyScreenMicros;
}

// ---------------------------------------------------------------------------
// Pinned projections (single thread). These are the headline numbers.
// ---------------------------------------------------------------------------
static_assert(ProjectSingleRootVerify(kNominal).within_relay_budget,
              "nominal CPU single-thread must clear 900 ms");
static_assert(ProjectSingleRootVerify(kOptimistic).within_relay_budget);
static_assert(!ProjectSingleRootVerify(kConservative).within_relay_budget,
              "conservative single-thread tail breaches; mitigation required");
static_assert(ProjectSingleRootVerify(kConservative, 4).within_relay_budget,
              "4-way query parallelism restores margin without accel");
static_assert(ProjectNativeTreeVerifyMicros(kNominal) > 40ull * kRelayBudgetMicros,
              "341-node native fallback is >40x over budget: single-root "
              "recursion is the only relay-feasible architecture");

/** Dominant-cost witness: row-leaf sponges are >85% of all permutations. */
static_assert(100 * kTotalQueries *
                  (RowSpongePerms(kParentW + 1) * 2 + RowSpongePerms(kParentW)) /
                  PermsPerNode(kParentW, kParentMerkleDepth, kParentFolds,
                               kTotalQueries) >=
              85);

// ---------------------------------------------------------------------------
// Gate. The MODEL is executable; the gap 10 closure additionally requires a
// measured run on target relay hardware that lands inside the envelope
// bracket [optimistic, conservative] for every projected component.
// ---------------------------------------------------------------------------
inline constexpr bool kRCStage3VerifyCostModelExecutable = true;
inline constexpr bool kRCStage3ProductionVerifyPerformanceMeasured = false;

static_assert(kRCStage3VerifyCostModelExecutable);
static_assert(!kRCStage3ProductionVerifyPerformanceMeasured);

} // namespace matmul::v4::rc::verify_cost_model

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFY_COST_MODEL_H
