// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MLINK_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MLINK_H

// Executable cross-shard equality link (M-LINK / P2).
//
// The relation-local partitioner (matmul_v4_rc_stage3_relation_local_sharding)
// emits one CrossShardEqualityLinkV1 obligation for every duplicated global
// trace column: the transported cell values of that column must be identical in
// the anchor shard and every replica shard. Multiset equality over the VALUE
// alone permits a row permutation, so the obligation is over the (row_index,
// value) tuple, tagged row-first.
//
// That header only *schedules* the six Rdep columns (INV1/2, TERM1/2, RUN1/2)
// per incident link; no code ever evaluated the fraction accumulator, checked
// the root=0 pin, or scored the challenge-injectivity floor. This module is the
// executable realization: an additive Fp3 LogUp-fraction accumulator over the
// (row_index, value) tuples, with two independent post-commitment lanes, a
// single global epsilon (one batched accumulator per lane, not a 2*Lambda
// per-link union), and a root=0 terminal pin.
//
// It is a real, runnable constraint that fires on a mismatched cross-shard
// value and is 0 on an honest witness. It is NOT a certified theorem: the
// FormalSoundnessReady flag below stays false and no certified_bits are minted.

#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_relation_local_sharding.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_mlink {

using gkr_field::Fp3;

inline constexpr char kMLinkChallengeDomainV1[] =
    "BTX_RC_STAGE3_MLINK_DUAL_FP3_LOGUP_CHALLENGE_V1";

/** Conservative log2|Fp3| after canonicalization margin (shared with the
 *  global soundness ledger's kConservativeFp3Bits). */
inline constexpr double kMLinkConservativeFp3Bits = 189.0;
/** Proof-internal FS/FRI query grind already charged elsewhere; subtracted so
 *  the M-LINK floor composes on the same basis as the composition ledger. */
inline constexpr double kMLinkGrindingBits = 40.0;
/** Canonical production site count (matches kCanonicalProductionSites). */
inline constexpr uint64_t kMLinkCanonicalProductionSites = 37'488'397ULL;
/** Registered CTL buses charged as independent per site. */
inline constexpr uint32_t kMLinkCtlBusesPerSite = 52;
/** Enforced per-bus event cap (matches kRCStage3CtlMaxEvents = 2^24). */
inline constexpr uint32_t kMLinkCtlEventsPerBus = 1U << 24;
/** Threat-model bar: q*=76 amortization game; a per-statement algebraic term
 *  must clear this many bits to be discountable. The 64-bit bar is the weaker
 *  minimum-acceptance line the report is asked to compare against. */
inline constexpr double kMLinkThreatModelQStarBar = 76.0;
inline constexpr double kMLinkMinimumAcceptanceBar = 64.0;

/** One transported cell of a duplicated global column: the (row_index, value)
 *  tuple actually committed by a shard. */
struct MLinkCellV1 {
    uint64_t row_index{0};
    Fp3 value{};

    bool operator==(const MLinkCellV1&) const = default;
};

/** One cross-shard equality obligation with its witnessed cells. anchor_cells
 *  and replica_cells are the full (row_index, value) multisets of the shared
 *  global column as committed by the two shards. */
struct MLinkObligationV1 {
    uint32_t link_index{0};
    uint32_t global_column{0};
    uint32_t anchor_shard{0};
    uint32_t replica_shard{0};
    std::vector<MLinkCellV1> anchor_cells;
    std::vector<MLinkCellV1> replica_cells;
};

/** Two independent LogUp lanes, each (gamma, alpha, beta):
 *   - alpha compresses the tuple:  t = row_index + alpha * value
 *   - gamma is the fraction offset: frac = 1 / (gamma - t)
 *   - beta batches all links into ONE accumulator (link power beta^{k+1}).
 *  Drawn AFTER every ordered shard R0 root is committed, so the challenges
 *  depend on the commitments and never the reverse (no Fiat-Shamir fixed
 *  point). */
struct MLinkChallengesV1 {
    Fp3 gamma[2]{};
    Fp3 alpha[2]{};
    Fp3 beta[2]{};
    uint32_t draw_counter{0};
    bool drawn_after_all_shard_commitments{true};
    bool degenerate_free{false};
};

/** Derive the dual lanes from the ordered shard roots and manifest commitment.
 *  Rejection-samples the draw counter until no denominator collides with a
 *  committed tuple in either lane for the supplied obligations (bounded). */
[[nodiscard]] MLinkChallengesV1 DeriveMLinkChallengesV1(
    const std::vector<uint256>& ordered_shard_roots,
    const uint256& manifest_commitment,
    const std::vector<MLinkObligationV1>& obligations,
    uint32_t max_draws = 64);

struct MLinkLaneEvalV1 {
    Fp3 accumulator_root{};
    bool root_is_zero{false};
    /** Per-row degree-2 inverse witness inv*(gamma - t) - 1 == 0 held for every
     *  cell in this lane (guards a degenerate gamma). */
    bool inverse_witness_consistent{false};
    /** First link whose batched bracket was non-zero, or UINT32_MAX. */
    uint32_t first_nonzero_link{0xFFFFFFFFu};
};

struct MLinkEvalV1 {
    bool executable{false};
    uint32_t link_count{0};
    uint64_t tuple_count{0};
    MLinkLaneEvalV1 lane[2]{};
    /** Honest witness: both lane roots are 0. */
    bool honest_all_roots_zero{false};
    /** Tamper: at least one lane root is non-zero (the link fires). */
    bool link_fires{false};
    uint32_t violated_link_index{0xFFFFFFFFu};
    std::string note;
};

/** Execute the additive dual-lane Fp3 LogUp-fraction accumulator with the
 *  root=0 pin. This is the M-LINK constraint itself. */
[[nodiscard]] MLinkEvalV1 EvaluateMLinkV1(
    const std::vector<MLinkObligationV1>& obligations,
    const MLinkChallengesV1& challenges);

/** Per-(shard, local_column) committed cell multiset, keyed exactly as the
 *  manifest's CrossShardEqualityLinkV1 references them. This is the honest
 *  prover witness for the transported columns. */
struct MLinkManifestWitnessV1 {
    std::map<std::pair<uint32_t, uint32_t>, std::vector<MLinkCellV1>> shard_column_cells;
};

/** Build obligations directly from the sharding manifest's equality links plus
 *  the transported-column witness, so the executable check consumes the real
 *  CrossShardEqualityLinkV1 obligations (feeds the composition). Returns
 *  nullopt with *why set if the witness is missing a referenced column. */
[[nodiscard]] std::optional<std::vector<MLinkObligationV1>>
BuildMLinkObligationsFromManifestV1(
    const stage3_relation_local_sharding::RelationLocalShardManifestV1& manifest,
    const MLinkManifestWitnessV1& witness,
    std::string* why = nullptr);

/** Soundness score of the executable construction. */
struct MLinkSoundnessV1 {
    uint64_t event_envelope{0};
    double site_log2{0.0};
    double event_log2{0.0};
    /** Single global gamma-injectivity floor per lane (bits). ONE epsilon for
     *  the whole M-LINK because all links share one batched accumulator and
     *  one global (gamma, alpha, beta) draw per lane. */
    double gamma_injectivity_floor_bits{0.0};
    /** ε_mlink reported as the single-lane floor (conservative; the dual lane
     *  only strengthens it). */
    double epsilon_mlink_bits{0.0};
    bool one_global_epsilon{true};
    bool dual_independent_lanes{true};
    bool clears_minimum_acceptance_bar{false};
    bool clears_qstar_76_threat_bar{false};
    std::string note;
};

[[nodiscard]] MLinkSoundnessV1 AssessMLinkSoundnessV1(uint64_t distinct_tuple_events = 0);

/** The dual-lane fraction-accumulator arithmetic is implemented and exercised
 *  (this is what backs the composition ledger's
 *  `ctl_dual_lane_arithmetic_executable` flag with a real evaluator rather than
 *  a config-only predicate). */
[[nodiscard]] bool MLinkDualLaneArithmeticExecutable();

/** The composition-ledger flag this executable link satisfies. */
inline constexpr char kMLinkSatisfiedCompositionLedgerFlag[] =
    "ctl_dual_lane_arithmetic_executable";

/** Executable and tamper-tested, but not a certified soundness theorem. Stays
 *  false until an end-to-end recursive-consumption theorem earns it. */
inline constexpr bool kMLinkFormalSoundnessReady = false;
static_assert(!kMLinkFormalSoundnessReady);

} // namespace matmul::v4::rc::stage3_mlink

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MLINK_H
