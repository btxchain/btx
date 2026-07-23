// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_SAMPLED_H
#define BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_SAMPLED_H

#include <arith_uint256.h>
#include <matmul/matmul_v4_rc.h>      // RCEpisodeParams, RCMerkleProof
#include <matmul/matmul_v4_rc_gkr.h>  // RCGkrProofV7 + the sampled-provenance seam
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// SUBLINEAR proof-of-work EPISODE VERIFIER — Fiat–Shamir-sampled per-layer
// checking with random-projection (Freivalds) matrix verification.
//
// Replaces the O(N) full re-execution (GroundEpisodeInCircuit / the compact
// AIR-quotient shard loop) with an O(λ·per-layer + λ·log N) check: draw λ
// layers by a public post-commitment coin, and for EACH sampled layer verify
// (a) its committed extract_out opens against round_roots (O(log N) Merkle
// path — the validator does NOT recompute the O(N) tile-tree root; the miner's
// committed root is trusted because it is target-bound, resolved question (c)
// of stage-c-sublinear-verification-comparison.md), (b) its GEMM A·B=Y by
// Freivalds random projection (O(mk+kn+mn), NEVER O(mkn)), (c) the Extract glue
// (extract_in→extract_out + the accumulator/residual relation) natively for
// that one layer, and (d) the chained-operand Λ wiring (A,B == referenced prior
// layers' extract_out).
//
// SAMPLING UNIT — whole GEMM layers of the canonical layout Λ whose extract_out
// is committed into the round tile-tree stream (SV, Fwd, Bwd, Wgrad). QKt is
// NOT directly sampleable: its output S is never placed in a round stream (it
// is consumed only as SV's A operand, bound transitively by the chain), so it
// has no O(log N) opening of its own — see RESIDUAL notes below and the report.
//
// FS-BINDING (unbiasable). The λ sampled indices derive from base_seed =
// RCGkrFsSeedV7(header,height,params,target,claimed_digest,sigma,round_roots),
// which already absorbs the full round_roots vector hence every committed tile
// output and the target. Moving the sample set requires a new base_seed, which
// requires new round_roots → a new digest → a fresh PoW trial (one grind).
// There is no cheap "same episode, different sample" move.
//
// RESIDUAL ρ*. This is economic DETERRENCE, not completeness: an UNSAMPLED
// tampered layer passes. A profit-maximising miner's largest worthwhile fake
// fraction is ρ* ≈ ln(κ)/λ (κ = mining gross margin); at λ=256, κ=2 that is
// ≈ 0.27 %, at competitive κ=1.1 it is ≈ 0.037 %. The Freivalds statistical
// error is ≤ 2^(−63·reps) per layer — ~83 bits below ρ*, so it is invisible
// under the sampling residual (reps is margin only). The unsampled-layer test
// asserts this boundary explicitly (deterrence, not a bug).
//
// DISCIPLINE. Additive and SHADOW/measurement only; never consensus until an
// explicit gate flips (exactly like VerifyWinnerProofV7Compact). Composes
// against the frozen Fable primitive FreivaldsCheckGemm
// (matmul_v4_rc_freivalds.h); arbiter OFF; does not modify alg_hash/fri/
// air_quotient/air_recurse; SHA/ExactReplay paths intact.
// ============================================================================

namespace matmul::v4::rc {

/** λ — number of Fiat–Shamir-sampled layers (stage-c §2.5 recommendation). */
inline constexpr uint32_t kRCFreivaldsSampleCount = 256;
/** Freivalds projections per sampled layer. reps=1 already clears the ~2^-64
 *  consensus scale (2^-63); reps is exposed for margin only and the sampling
 *  residual ρ* dominates regardless (see banner). */
inline constexpr uint32_t kRCFreivaldsReps = 2;
/** Domain tag: FS derivation of the λ sampled layer indices. */
inline constexpr char kRCFreivaldsSampleTag[] = "BTX_RC_FRVS_SAMPLE_V1";
/** Domain tag: per-layer Freivalds challenge seed derivation. */
inline constexpr char kRCFreivaldsGemmSeedTag[] = "BTX_RC_FRVS_GEMM_V1";
/** Carrier format version. */
inline constexpr uint32_t kRCFreivaldsSampledCarrierVersion = 1;

// ---------------------------------------------------------------------------
// FS sample derivation.
// ---------------------------------------------------------------------------

/**
 * Draw min(lambda, n_units) DISTINCT unit indices in [0, n_units) by a domain-
 * separated SHA256d counter — idx = reduce(SHA256d(kRCFreivaldsSampleTag ‖
 * base_seed ‖ LE32(counter))) mod n_units, incrementing counter and rejecting
 * duplicates. Deterministic, unbiasable, verifier-recomputable. Returns the
 * indices in draw order (a caller may sort). n_units==0 → empty.
 */
[[nodiscard]] std::vector<uint32_t> FreivaldsSampleLayers(const uint256& base_seed,
                                                          uint32_t n_units, uint32_t lambda);

/** Per-layer Freivalds challenge seed: SHA256d(kRCFreivaldsGemmSeedTag ‖
 *  base_seed ‖ LE32(layer_index)). Bound to the episode via base_seed. */
[[nodiscard]] uint256 FreivaldsLayerChallengeSeed(const uint256& base_seed,
                                                  uint32_t layer_index);

// ---------------------------------------------------------------------------
// Instrumentation / timing (proves the sublinearity: flat in total layers).
// ---------------------------------------------------------------------------

struct RCFreivaldsSampledTiming {
    bool ok{false};
    double total_s{0.0};
    double gates_s{0.0};        // trivial/target/digest/round-seed gates
    double sample_s{0.0};       // FS sample derivation
    double perlayer_s{0.0};     // the λ sampled-layer checks
    uint32_t n_units_total{0};  // sampleable units in the episode (Λ minus QKt)
    uint32_t n_sampled{0};      // == min(λ, n_units_total)
    uint32_t n_layers_checked{0};   // COUNTER: layers actually touched (== n_sampled)
    uint32_t n_freivalds_calls{0};  // == n_sampled
    uint64_t n_extract_tiles{0};    // Extract tiles re-executed (Σ over sampled layers)
    uint32_t n_merkle_openings{0};  // covering leaves opened (O(λ·leaves))
    uint64_t n_merkle_hashes{0};    // SHA compressions in the openings (O(λ·log N))
    std::string note;
};

/**
 * SUBLINEAR sampled verifier over a FULL v7 proof's carried wires. Runs the
 * same cheap trivial/target/digest/round_seeds/round_roots gates as
 * VerifyWinnerProofV7Compact, then the λ sampled-layer checks (a)–(d). Verifier
 * cost = O(λ·per-layer + λ·log N); the Freivalds/Extract/chain work touches
 * exactly n_sampled layers regardless of the total layer count. Reasons are
 * prefixed "v7fs:". Shadow/measurement only — NEVER consensus.
 *
 * `lambda` defaults to kRCFreivaldsSampleCount; tests pass a small λ to exhibit
 * flat-in-N cost across episode sizes.
 */
[[nodiscard]] bool VerifyEpisodeFreivaldsSampled(
    const RCGkrProofV7& proof, const CBlockHeader& header, int32_t height,
    const arith_uint256& target, std::string* why = nullptr,
    RCFreivaldsSampledTiming* out_timing = nullptr,
    uint32_t lambda = kRCFreivaldsSampleCount);

// ---------------------------------------------------------------------------
// RELAY-OPTIMIZED sampled-proof carrier — only the λ sampled layers' bytes +
// tile-tree openings, not all wires. The miner selects+opens the λ layers; the
// verifier operates on the carrier ALONE (no full-episode wires present), which
// is what makes the relayed proof — and hence the whole flow — sublinear.
// ---------------------------------------------------------------------------

/** One sampled layer's carried bytes + its extract_out tile-tree opening. */
struct RCFreivaldsSampledLayer {
    uint32_t layer_index{0};   // index into the Λ enumeration (== wire index)
    uint32_t round{0};         // which round_root the opening targets
    RCGkrLayerKind kind{};
    uint32_t m{0}, n{0}, k{0};
    std::vector<int8_t> A;            // operand A (int8, m×k)
    std::vector<int8_t> B;            // operand B (int8, k×n)
    std::vector<int64_t> Y;           // GEMM product (int64, m×n)
    std::vector<int64_t> extract_in;  // pre-Extract accumulator (int64, m×n)
    std::vector<int8_t> extract_out;  // Extract output (int8, m×n)
    // Tile-tree opening of extract_out into round_roots[round]. extract_out
    // occupies stream bytes [stream_offset, stream_offset + m*n); the covering
    // leaves are [first_leaf, first_leaf + leaf_bytes.size()). Each carried leaf
    // is the FULL T_leaf stream bytes (neighbour bytes included) so its hash and
    // Merkle path reproduce round_roots[round]; the overlap with extract_out is
    // checked byte-for-byte.
    uint64_t stream_offset{0};
    uint32_t first_leaf{0};
    std::vector<std::vector<uint8_t>> leaf_bytes;
    std::vector<RCMerkleProof> leaf_proofs;
};

struct RCFreivaldsSampledCarrier {
    uint32_t version{kRCFreivaldsSampledCarrierVersion};
    RCEpisodeParams episode{};
    int32_t height{0};
    uint256 claimed_digest{};
    uint256 pow_bind{};
    uint256 episode_sigma{};
    std::vector<uint256> round_seeds;
    std::vector<uint256> round_roots;
    uint32_t lambda{kRCFreivaldsSampleCount};
    std::vector<RCFreivaldsSampledLayer> sampled;  // exactly n_sampled entries
};

/**
 * Miner-side builder: run the same gates + FS sample derivation as the verifier
 * over the honest proof, then for each sampled layer copy its wire bytes and
 * OPEN its extract_out covering leaves against round_roots. O(N) to build the
 * round leaves once (intrinsic to having built the tile-tree for the digest),
 * O(λ·log N) openings emitted. Returns false on any structural inconsistency.
 */
[[nodiscard]] bool BuildFreivaldsSampledCarrier(
    const RCGkrProofV7& proof, const CBlockHeader& header, int32_t height,
    const arith_uint256& target, RCFreivaldsSampledCarrier& out,
    std::string* why = nullptr, uint32_t lambda = kRCFreivaldsSampleCount);

/**
 * SUBLINEAR verifier over the carrier ALONE. Re-derives base_seed and the λ
 * sampled indices from the carried commitments, and for each carried layer runs
 * the SAME (a)–(d) checks against the carried bytes + openings. Never touches an
 * O(N) structure. Reasons prefixed "v7fs:". Shadow/measurement only.
 *
 * BOUNDARY (documented, not a bug): the carrier does not re-derive leaf-operand
 * PRF expansions and cannot bind a QKt-sourced chained operand (SV.A = S) to the
 * root; those operand bytes are covered only by the Freivalds GEMM statement +
 * target-bound digest, and are the "authenticated-bytes" refinement follow-on.
 * The full-wires VerifyEpisodeFreivaldsSampled DOES enforce chained byte-equality
 * against the referenced wires.
 */
[[nodiscard]] bool VerifyEpisodeFreivaldsSampledCarrier(
    const RCFreivaldsSampledCarrier& carrier, const CBlockHeader& header, int32_t height,
    const arith_uint256& target, std::string* why = nullptr,
    RCFreivaldsSampledTiming* out_timing = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_SAMPLED_H
