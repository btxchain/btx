// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_AIR_EPISODE_H
#define BTX_MATMUL_MATMUL_V4_RC_AIR_EPISODE_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// ENC_RC — EPISODE-LEVEL AIR constraint-quotient instantiation (Fp3).
//
// GOAL (verifier-sublinearity of the LOW-DEGREE per-row rules). The v7 episode
// verifier grounds the carried witness by GroundEpisodeInCircuit — an O(N)
// scan that re-runs, PER ROW, the in-circuit MxExpand SHA XOF, the Extract
// sampler trace (ChaCha + scale-SHA + per-candidate constraints) and the
// tile-tree SHA. This module lifts the rules of that scan which ARE low-degree
// polynomial identities over the committed columns into ONE AIR
// constraint-quotient system (matmul_v4_rc_air_quotient.h) whose verification
// is O(Q) per shard: Q = 128 FS query points, no row scan.
//
// TRACE (row space; one global row index, sharded into power-of-two
// sub-traces of min(kEpisodeAirMaxShardRows, next_pow2(total)) rows each):
//   rows [0, E1)        — one row per Extract OUTPUT ELEMENT, layer-major in
//                          Λ order, row-major within a layer (E1 = Σ m·n).
//   rows [E1, E1+E2)    — one row per LEAF-OPERAND ELEMENT, leaf-major in Λ
//                          order (E2 = Σ erows·ecols over leaf operands).
//   rows [0, n_layers)  — additionally carry the per-layer GEMM sumcheck
//                          endpoint claims in three dedicated public columns
//                          (they overlap the element rows; disjoint columns).
// Layout offsets are PUBLIC functions of the episode params (every m·n and
// erows·ecols is a multiple of 32), so all selectors are preprocessed.
//
// PER-ROW RULES ARITHMETIZED (everywhere / transition / boundary):
//   • E2M1 acceptance + booleanity: the 4 nibble bits are boolean and the
//     acceptance selector AirAcceptPoly(nb) equals 1 (padding rows carry
//     nibble 0, an accepted code). AirAcceptPoly's rejected form factors as
//     (1−b2)·inner; the module commits `inner` as an auxiliary column with a
//     degree-2 definitional constraint so the acceptance rule is degree 2 —
//     the max composed degree stays 2, the quotient length N−1, and
//     n_coeffs = N (4× cheaper than the naive degree-4 composition). The
//     factorization is cross-checked against AirAcceptPoly in the tests.
//   • Dequant identity (MxExpand §5.7 AND Extract C-E10 share it):
//         val = mu · (1 + e0)(1 + 3·e1)     (= mu · 2^e, e = e0 + 2·e1)
//     with the SCALE BITS PREPROCESSED: the per-tile Extract scale
//     (DeriveMatExpandMxScale(prf, i, bj)) and the per-32-block MxExpand
//     scale-XOF codes are PUBLIC functions of the header-derived PRF keys /
//     operand seeds, so the verifier pins them as preprocessed columns.
//   • extract_in binding (§5.7): selElem·(ein − y) − selFwd·a = 0 (the H5
//     Fwd residual ein = Y + A; ein = Y elsewhere).
//   • Leaf-operand seed binding: selLeaf·(val − expect) = 0 where `expect` is
//     the PREPROCESSED canonical MxExpand expansion of the (public) operand
//     seed — regenerated natively by the verifier with PLAIN SHA-256 (fast),
//     not with the constraint-checked in-circuit compressions of the row scan.
//   • T_M LogUp membership of (nib, 1, mu) against the canonical mantissa
//     table, as a RUNNING-SUM TRANSITION system: per-row fractional witnesses
//         phi·(α − w) = selElem + selLeaf,   psi·(α − t) = m,
//     accumulator S' = S + (phi − psi) (transition), S(0) = 0 (first row) and
//     S + phi − psi = 0 (last row) ⇒ Σφ = Σψ per shard. The table side t is
//     PREPROCESSED (canonical T_M fingerprints in γ) — the Theorem-5.1
//     "table := witness" clone dies at the preprocessed-root regeneration.
//   • GEMM sumcheck endpoint: gf − a·b = 0 over the three preprocessed claim
//     columns (the public per-layer final_eval / a_eval / b_eval), enforced
//     through the same quotient identity at the query points.
//
// WHAT IS **NOT** ARITHMETIZED HERE (honest residual, per the module-header
// honesty discipline of matmul_v4_rc_air_quotient.h):
//   • SHA-256 / SHA-256d (MxExpand XOF blocks, scale SHA, tile tree) and the
//     ChaCha20 keystream: high algebraic degree; the tile-tree closure stays
//     the bounded DIRECT check (CheckTileTreeInCircuit /
//     CheckSha256dInCircuit) in the compact verify path, and the seed→stream
//     bindings enter as verifier-regenerated PREPROCESSED columns (native
//     plain-SHA recompute of public functions, not per-row in-circuit AIRs).
//   • The per-candidate Extract sampler transition system (pos/liveness/
//     golden-mix over the ChaCha candidate stream): its row count is
//     witness-dependent (rejection sampling), and its keystream binding is
//     the ChaCha residual above. The accepted-slot rules that ARE fixed-layout
//     (acceptance nibble, T_M membership, dequant, extract_in binding) are
//     arithmetized; the candidate-level walk stays with the row-scan AIR (and
//     is exercised per tile by the RcSampler instantiation in
//     matmul_v4_rc_air_quotient.h).
//   • Chained-operand (Λ wiring) equality across layers and the binding of
//     this AIR's witness columns to the v7 batched-FRI roots: byte-compare /
//     deterministic-builder in the compact SHADOW path (a permutation-argument
//     lift is the production step). This module is a measurement scaffold —
//     arbiter stays OFF, nMatMulRCHeight = INT32_MAX, never consensus.
// ============================================================================

namespace matmul::v4::rc::air_episode {

using gkr_field::Fp3;

/** Maximum shard height (rows per AIR instance; power of two). The episode
 *  row space is cut into shards of height min(kEpisodeAirMaxShardRows,
 *  next_pow2(total rows)) — a public function of the layout — each an
 *  independent constraint-quotient proof, O(Q) verification per shard. The
 *  per-shard verify cost is dominated by the Q = 128 query-point Merkle
 *  openings and grows only logarithmically with the shard height, while the
 *  shard COUNT (the linear residual of this sharding) shrinks
 *  proportionally, so the largest shard the prover's memory tolerates is
 *  strictly better for the verifier. 2^16 rows ⇒ ~5 GB peak prover memory
 *  per shard (LDE + Merkle trees over the 16× blowup domain). */
inline constexpr uint32_t kEpisodeAirMaxShardRows = 1u << 16;

// ---------------------------------------------------------------------------
// Column layout. Epoch-1 columns (0..17) feed the per-shard γ/α FS derivation;
// the LogUp columns (tfp, phi, m, psi, S) are epoch-2 (built AFTER γ, α).
// (P) = preprocessed: verifier-regenerated canonical values, root-pinned.
// ---------------------------------------------------------------------------
enum EpisodeAirCol : uint32_t {
    kEpSelElem = 0,   // (P) 1 on element rows
    kEpSelFwd,        // (P) 1 on element rows of H5 fwd-residual layers
    kEpSelLeaf,       // (P) 1 on leaf-operand rows
    kEpScaleE0,       // (P) scale bit 0 (public per tile / per 32-block)
    kEpScaleE1,       // (P) scale bit 1
    kEpLeafExpect,    // (P) canonical MxExpand expansion value (leaf rows)
    kEpGemmGf,        // (P) per-layer sumcheck endpoint gf (rows 0..L-1)
    kEpGemmA,         // (P) per-layer opening a_eval
    kEpGemmB,         // (P) per-layer opening b_eval
    kEpVal,           // committed value: extract_out (elem) / operand (leaf)
    kEpMu,            // mantissa
    kEpNb0, kEpNb1, kEpNb2, kEpNb3,  // accepted-nibble bits
    kEpY,             // committed GEMM product Y (element rows)
    kEpA,             // committed operand A at the same index (fwd rows)
    kEpEin,           // pre-Extract accumulator extract_in (element rows)
    /** Degree-reduction aux: nbAnd01 = b0·b1 (definitional, degree 2). */
    kEpNbAnd01,
    /** Degree-reduction aux: inner factor of AirAcceptPoly's rejected form
     *  (rejected = (1−b2)·inner, inner = (1−b3)·b0 + b3·(1−b1) + b3·nbAnd01);
     *  definitional degree-2 constraint via nbAnd01. */
    kEpRejInner,
    /** Degree-reduction aux: muSc = mu·(1+e0), so dequant stays degree 2. */
    kEpMuSc,
    kEpEpoch1Cols,    // = 21
    kEpTfp = kEpEpoch1Cols,  // (P) canonical T_M fingerprint table (γ-dependent)
    kEpPhi,           // 1/(α − w) on active rows
    kEpM,             // table multiplicity (rows 0..15)
    kEpPsi,           // m/(α − t)
    kEpS,             // LogUp running sum
    kEpNumCols        // = 26
};

// ---------------------------------------------------------------------------
// Public layout (all Λ outputs / proof-public values).
// ---------------------------------------------------------------------------

struct EpisodeAirLayer {
    uint32_t m{0}, n{0};
    bool fwd_residual{false};
    uint256 extract_prf{};  // public per-layer Extract PRF key (scale source)
};

struct EpisodeAirLeaf {
    uint256 seed{};         // public operand-expansion seed
    uint32_t rows{0}, cols{0};  // untransposed expansion dims (%32 == 0)
};

struct EpisodeAirGemmClaim {
    Fp3 gf{};  // final_eval (sumcheck chain end)
    Fp3 a{};   // a_eval
    Fp3 b{};   // b_eval
};

struct EpisodeAirLayout {
    std::vector<EpisodeAirLayer> layers;
    std::vector<EpisodeAirLeaf> leaves;
    std::vector<EpisodeAirGemmClaim> gemm;
};

/** Prover-side witness references (the carried v7 wire columns). */
struct EpisodeAirLayerWitness {
    const std::vector<int8_t>* A{nullptr};            // m×k (residual source)
    const std::vector<int64_t>* Y{nullptr};           // m×n
    const std::vector<int64_t>* extract_in{nullptr};  // m×n
    const std::vector<int8_t>* extract_out{nullptr};  // m×n
};

struct EpisodeAirWitness {
    std::vector<EpisodeAirLayerWitness> layers;   // 1:1 with layout.layers
    std::vector<std::vector<int8_t>> leaf_committed;  // 1:1 with layout.leaves
};

// ---------------------------------------------------------------------------
// Proof containers + API.
// ---------------------------------------------------------------------------

struct EpisodeAirProof {
    std::vector<air_quotient::AirQuotientProof<Fp3>> shards;
};

struct EpisodeAirProveOptions {
    /** Commit shards whose trace violates a constraint (adversarial/self-test
     *  use — the verifier must reject them at the query points). */
    bool force_commit_on_violation{false};
    /** Nonzero: commit every shard quotient at this length instead of the
     *  declared bound (self-test; the structural degree check must reject). */
    uint32_t quotient_len_override{0};
};

struct EpisodeAirProveResult {
    bool ok{false};
    bool division_exact{true};  // AND over shards
    std::string note;
    uint32_t n_shards{0};
    uint64_t n_rows{0};         // pre-padding global rows (E1 + E2)
    double prove_s{0.0};
    EpisodeAirProof proof;
};

struct EpisodeAirVerifyStats {
    uint32_t n_shards{0};
    uint64_t n_rows{0};
    /** Native regeneration of the public/preprocessed data (leaf XOF
     *  expansions with plain SHA-256, per-tile scales, selectors). */
    double preprocess_s{0.0};
    /** AirQuotientVerify over all shards — the O(shards·Q) part. */
    double quotient_s{0.0};
};

/**
 * Prover: build the sharded trace from the carried witness (TraceTile per
 * Extract tile for the accepted-slot nibbles; native XOF for leaf nibbles),
 * derive per-shard γ/α by FS over the committed epoch-1 column roots, and run
 * AirQuotientProve per shard. Refuses to commit on a violated constraint
 * unless opt.force_commit_on_violation.
 */
[[nodiscard]] EpisodeAirProveResult ProveEpisodeAirQuotient(
    const EpisodeAirLayout& layout, const EpisodeAirWitness& witness,
    const uint256& fs_seed, const EpisodeAirProveOptions& opt = {});

/**
 * Verifier: regenerate the public data natively (plain SHA-256 XOF for leaf
 * expectations, per-tile scale bytes, selectors), re-derive per-shard γ/α from
 * the committed epoch-1 roots, and run AirQuotientVerify per shard (structural
 * degree bounds, batched FRI, preprocessed root pinning, quotient identity at
 * the Q = 128 query points). NO row scan of the per-row rules.
 */
[[nodiscard]] bool VerifyEpisodeAirQuotient(const EpisodeAirLayout& layout,
                                            const EpisodeAirProof& proof,
                                            const uint256& fs_seed,
                                            std::string* why = nullptr,
                                            EpisodeAirVerifyStats* stats = nullptr);

} // namespace matmul::v4::rc::air_episode

#endif // BTX_MATMUL_MATMUL_V4_RC_AIR_EPISODE_H
