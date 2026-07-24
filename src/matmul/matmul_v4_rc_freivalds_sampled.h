// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_SAMPLED_H
#define BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_SAMPLED_H

#include <arith_uint256.h>
#include <matmul/matmul_v4_rc.h>      // RCEpisodeParams, RCMerkleProof
#include <matmul/matmul_v4_rc_gkr.h>  // RCGkrProofV7 + the sampled-provenance seam
#include <primitives/block.h>
#include <span.h>
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
// fraction is ρ* ≈ ln(κ)/λ (κ = mining gross margin); at the deployed λ=512
// (kRCFreivaldsSampleCount), κ=2 that is ≈ 0.13 %, at competitive κ=1.1 it is
// ≈ 0.019 %. The full-wires path's Freivalds statistical error is ≤ 2^(−63·reps)
// per layer — far below ρ*, so it is invisible under the sampling residual (reps
// is margin only; the v3 anchored carrier recomputes exactly and adds no such
// error). The unsampled-layer test asserts this boundary (deterrence, not a bug).
//
// CONSENSUS ROLE (datacenter profile — 2026-07 owner-authorized activation).
// UNDER nMatMulRCProfile == 2 (the datacenter dims) this sampled verifier IS the
// consensus accept/reject AUTHORITY in CheckMatMulProofOfWork_RC: at the
// 16×-heavier datacenter episode ExactReplay cannot re-run the workload inside
// the block-verify budget, so the sublinear sampled check decides validity. This
// authority is DETERRENCE-based, NOT complete and NOT audited: an UNSAMPLED
// tampered layer passes, with residual cheatable fraction ρ* ≈ ln(κ)/λ ≈ 0.13 %
// (λ=512, κ=2) — see RESIDUAL above. It is an explicit owner risk decision; it is
// NOT a formal-soundness or audit claim (the external cryptographic audit of the
// FS coin / Freivalds composition / T-BIND / opening soundness remains OPEN, and
// kRCGkrFormalSoundnessReady — which gates the SEPARATE GKR/SNARK arbiter, not
// this path — stays false). ExactReplay is retained as the ε=0 async ARBITER /
// dispute path a full node can run off the hot path.
//
// Under nMatMulRCProfile == 1 (epoch-0 base dims) this path is NOT consensus:
// ExactReplay is the sole authority exactly as before, and the verifier here is
// shadow/measurement only. Composes against the frozen Fable primitive
// FreivaldsCheckGemm (matmul_v4_rc_freivalds.h); does not modify alg_hash/fri/
// air_quotient/air_recurse; the ExactReplay path is intact for both profiles.
// ============================================================================

namespace matmul::v4::rc {

/** λ — number of Fiat–Shamir-sampled layers. Raised 256→512 (aicompute-alignment-
 *  review.md §5.2: "cheap soundness insurance"): halves the deterrence residual
 *  ρ* ≈ ln(κ)/λ from ≈0.27%→0.13% (κ=2) / 0.037%→0.019% (competitive). The
 *  anchored per-tile carrier (below) keeps 512 sampled layers UNDER the 12 MiB relay
 *  ceiling at production dims because per-layer relay is bounded by the per-tile
 *  anchored footprint (extract_out + one A-row leaf + Merkle paths), not the full
 *  operand size. */
inline constexpr uint32_t kRCFreivaldsSampleCount = 512;

// ---------------------------------------------------------------------------
// ANCHORED per-tile carrier granularity (datacenter relay-ceiling fit + width
// unpin). Instead of opening a sampled layer's FULL operands (which at production
// dims exceed the 12 MiB carrier ceiling — a single Fwd Y is ~1 GiB int64, an SV
// A operand ~384 MiB int8), each sampled layer opens a BOUNDED set of random
// OUTPUT TILES; per tile the carrier relays the ANCHORED layer-input A-row (opened
// against round_roots, or PRF-regenerated) + the committed extract_out, and the
// verifier EXACT-RECOMPUTES the full contraction from PRF-regenerated weights
// (v3, scratchpad/sound-carrier-design.md §4). NOTE: this superseded the earlier
// v2 "segment-Freivalds" carrier — there are no longer relayed Y bytes, relayed
// contraction segments, or a Freivalds identity in the carrier path; every opened
// tile's GEMM is checked exactly. The per-sampled-layer relay is INDEPENDENT of
// m, n and the full k — it is
//   s_tile · [ T (extract_out) + T_leaf (anchored A-row leaf) + 2·(leaves·T_leaf
//              + path) ]
// with T = kRCMxBlockLen (one MX output block, a single output row × 32 cols),
// so a d_model > 4096 (or n_ctx-scaled) episode carries the SAME bytes — this is
// the width UNPIN. An output tile is a single (row i, 32-col block bj): contiguous
// in the round stream (clean O(log N) leaf opening) and exactly one Extract tile.
inline constexpr uint32_t kRCFreivaldsSegOutTiles = 2;     // output tiles / sampled layer (LIVE)
// LEGACY (v2 segment carrier): unused by the v3 anchored carrier, which recomputes
// the FULL contraction per tile rather than sampling contraction segments. Retained
// only so the FS SegPos derivation domain constants stay pinned.
inline constexpr uint32_t kRCFreivaldsSegContractSegs = 2; // contraction segments / tile (legacy)
inline constexpr uint32_t kRCFreivaldsSegContractLen = 64; // MX-aligned length / segment (legacy)
static_assert(kRCFreivaldsSegContractLen % 32 == 0, "segment length must be MX(32)-aligned");
static_assert(kRCFreivaldsSegOutTiles >= 1 && kRCFreivaldsSegContractSegs >= 1,
              "at least one output tile and one contraction segment must be sampled");
/** SOUNDNESS granularity (v3 anchored carrier). Each opened output tile's GEMM is
 *  recomputed EXACTLY from anchored operands over the FULL contraction [0,k), so
 *  the per-tile check is exact (no Freivalds error, no uncovered-contraction gap)
 *  and binds to the committed extract_out opened against round_roots. The only
 *  residual is the SAMPLING one: an UNSAMPLED layer is not checked at all — priced
 *  as ρ* (see RESIDUAL banner), NOT a per-tile soundness gap. This is the honest
 *  datacenter posture. */
/** Freivalds projections per sampled layer — used by the FULL-WIRES verifier
 *  (VerifyEpisodeFreivaldsSampled, FreivaldsCheckGemm) and the FreivaldsCheckGemm-
 *  Segments primitive, NOT by the v3 anchored carrier (which recomputes exactly).
 *  reps=1 already clears the ~2^-64 consensus scale (2^-63); reps is margin only
 *  and the sampling residual ρ* dominates regardless (see banner). */
inline constexpr uint32_t kRCFreivaldsReps = 2;
/** Domain tag: FS derivation of the λ sampled layer indices. */
inline constexpr char kRCFreivaldsSampleTag[] = "BTX_RC_FRVS_SAMPLE_V1";
/** Domain tag: per-layer Freivalds challenge seed derivation. */
inline constexpr char kRCFreivaldsGemmSeedTag[] = "BTX_RC_FRVS_GEMM_V1";
/** Domain tag: FS derivation of the per-layer output-tile + contraction-segment
 *  positions (segment carrier). */
inline constexpr char kRCFreivaldsSegPosTag[] = "BTX_RC_FRVS_SEGPOS_V1";
/** Carrier format version. v2: segment carrier (bounded per-layer relay).
 *  v3: fused-FFN ANCHORED per-tile carrier — the tautological segment/partial-cover
 *  branch is removed; each sampled DOWN tile relays the anchored A-row (X[l] row,
 *  opened against round_roots, or PRF-regenerated at l=0) + the committed
 *  extract_out, and the verifier recomputes H-row + Y-row from anchored operands
 *  (scratchpad/sound-carrier-design.md §4). */
inline constexpr uint32_t kRCFreivaldsSampledCarrierVersion = 3;

/** Upper bound on ONE sampled layer's serialized relay bytes in the v3 anchored
 *  carrier — a function of the per-tile anchored footprint (kRCFreivaldsSegOutTiles
 *  output tiles, each carrying extract_out + one anchored A-row leaf + Merkle
 *  paths), T_leaf and the tile-tree depth, and INDEPENDENT of the full operand size
 *  m·n·k. This is what keeps λ=512 sampled layers under the 12 MiB ceiling at
 *  production dims and unpins width (d_model > 4096 costs the same). Exposed for
 *  relay sizing/tests. */
[[nodiscard]] size_t RCFreivaldsSegLayerByteBound(const RCEpisodeParams& params);

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
    // Per-unit GEMM-check counter. In the full-wires VerifyEpisodeFreivaldsSampled
    // path this counts genuine Freivalds calls (FreivaldsCheckGemm), one per sampled
    // layer (== n_sampled). In the v3 anchored CARRIER path there is NO Freivalds —
    // the counter tallies EXACT per-tile recomputes (one per opened output tile), so
    // it is ≥ n_sampled there. The field name is kept for instrumentation continuity.
    uint32_t n_freivalds_calls{0};
    uint64_t n_extract_tiles{0};    // Extract tiles re-executed (Σ over sampled layers)
    uint32_t n_merkle_openings{0};  // covering leaves opened (O(λ·leaves))
    uint64_t n_merkle_hashes{0};    // SHA compressions in the openings (O(λ·log N))
    // Production verify-cost SPLIT (carrier path). Populated only when the caller
    // passes out_timing (the consensus path passes nullptr and pays nothing). Added
    // to localize the 0.9 s-budget miss: which of PRF regen / dense recompute /
    // Merkle dominates.
    double regen_s{0.0};        // Σ ExpandMxDequantInt8 (W_up d_model×d_ff, W_down d_ff×d_model, Q/K/V, X0)
    double recompute_s{0.0};    // Σ dense tile arith: X_row·W_up→H_row, H_row·W_down→Y (+SV S-row, S·V)
    double merkle_s{0.0};       // Σ CheckCoveringLeaf (A-row + extract_out covering leaves)
    double plan_s{0.0};         // four-phase carrier verifier: serial gates+plan wall time
    double prewarm_s{0.0};      // four-phase carrier verifier: deterministic operand prewarm wall time
    double unitcheck_s{0.0};    // four-phase carrier verifier: parallel unit-check wall time
    double reduce_s{0.0};       // four-phase carrier verifier: deterministic first-failure reduction
    uint32_t regen_misses{0};   // distinct PRF tensors expanded (cache misses)
    uint32_t regen_hits{0};     // cache hits (operand reuse within/across sampled layers)
    uint64_t regen_bytes{0};    // total int8 entries expanded (≈ regenerated bytes)
    uint32_t verify_threads{1}; // carrier verifier worker count; verdict/reason must be invariant
    bool recompute_vectorized{false}; // false = current scalar loops; set true when routed to ExactGemm
    std::string note;
};

/** True when the exact dense row×32-block recompute helper is using a compiled
 *  vector path on this host. The helper still falls back per-call when the
 *  contraction length cannot be safely accumulated in int32. */
[[nodiscard]] bool RCDenseRowBlockVectorizedAvailable();

/** Byte-exact row-vector × row-major matrix 32-column block:
 *      out[c] = Σ_t lhs[t] * rhs[t, rhs_col0 + c], c∈[0,31].
 *
 *  This is the verifier hot path for SV's S_row·V block and fused-FFN
 *  X_row·W_up / H_row·W_down tiles. Accelerated implementations must produce
 *  the same int64 outputs as the scalar loop. */
void RCDenseRowBlockExactI8(const int8_t* lhs, const int8_t* rhs, uint32_t k,
                            uint32_t rhs_cols, uint32_t rhs_col0,
                            int64_t out[kRCMxBlockLen]);

/** Same row×32-block contract, but `rhs_t` is rhs transposed to
 *  [rhs_cols][k], making each output-column dot product contiguous. Used for
 *  cached FFN W_up tensors where the verifier computes every H column. */
void RCDenseRowBlockTransposedExactI8(const int8_t* lhs, const int8_t* rhs_t, uint32_t k,
                                      uint32_t rhs_cols, uint32_t rhs_col0,
                                      int64_t out[kRCMxBlockLen]);

/** Byte-exact two-row variant for transposed RHS. On ARM I8MM this computes
 *  two sampled FFN H rows together and uses all four matrix-accumulate lanes.
 *  Fallback is exactly two RCDenseRowBlockTransposedExactI8 calls. */
void RCDenseTwoRowsBlockTransposedExactI8(const int8_t* lhs0, const int8_t* lhs1,
                                          const int8_t* rhs_t, uint32_t k,
                                          uint32_t rhs_cols, uint32_t rhs_col0,
                                          int64_t out0[kRCMxBlockLen],
                                          int64_t out1[kRCMxBlockLen]);

/** True when the packed ARM I8MM cache-format kernels pass their byte-identity
 *  self-test on this host. Packed layout is verifier-local only: it is derived
 *  deterministically from the prewarmed int8 tensor and never serialized. */
[[nodiscard]] bool RCDensePackedI8mmAvailable();

/** Pack a row-major RHS matrix [rows][cols] into the verifier-local SMMLA
 *  layout consumed by RCDense*PackedI8mmExactI8. Requires rows%8==0 and
 *  cols%kRCMxBlockLen==0. */
std::vector<int8_t> RCPackDenseI8mmOutputBlocks(const std::vector<int8_t>& rhs,
                                                uint32_t rows, uint32_t cols);

void RCDenseRowBlockPackedI8mmExactI8(const int8_t* lhs, const int8_t* rhs_packed,
                                      uint32_t k, uint32_t rhs_cols, uint32_t rhs_col0,
                                      int64_t out[kRCMxBlockLen]);

void RCDenseTwoRowsBlockPackedI8mmExactI8(const int8_t* lhs0, const int8_t* lhs1,
                                          const int8_t* rhs_packed, uint32_t k,
                                          uint32_t rhs_cols, uint32_t rhs_col0,
                                          int64_t out0[kRCMxBlockLen],
                                          int64_t out1[kRCMxBlockLen]);

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

/** One sampled OUTPUT TILE of one sampled layer: a single (row i, 32-col block bj)
 *  of the committed extract_out, plus the ANCHORED contraction operand needed to
 *  recompute it. v3 (fused-FFN anchored carrier, scratchpad/sound-carrier-design.md
 *  §4): NO relayed Y/segments — the verifier recomputes H-row + Y-row from the
 *  anchored A-row (X[l] row) and the PRF-regenerated weights, then compares against
 *  the committed extract_out. Relay is O(T_leaf + depth), independent of m,n,k. */
struct RCFreivaldsSampledTile {
    uint32_t row{0};   // output row i ∈ [0, m)
    uint32_t bcol{0};  // output 32-col block bj ∈ [0, n/32); cols [bj*32, bj*32+32)
    std::vector<int8_t> extract_out;  // committed Extract output eo[i, bj-block] (int8, T)
    // Anchored contraction input A-row (the LAYER INPUT row: X[l] row i for a DOWN
    // tile; S row i for SV). For a committed activation (DOWN, l≥1) this is one
    // T_leaf leaf opened against round_roots; for a PRF-regenerable input (DOWN
    // l=0 → X0 leaf; SV → S regenerated from Q,K) it is EMPTY and a_prf_regen=true.
    bool a_prf_regen{false};
    std::vector<uint8_t> a_row_leaf;   // T_leaf bytes (== A-row when row-aligned)
    uint64_t a_row_stream_offset{0};   // off_A in the source layer's stream region
    uint32_t a_row_leaf_index{0};
    RCMerkleProof a_row_proof;         // Merkle path of a_row_leaf to round_roots[round]
    // Tile-tree opening of extract_out into round_roots[round]. The block occupies
    // stream bytes [stream_offset, stream_offset + T); the covering leaves are
    // [first_leaf, first_leaf + leaf_bytes.size()). Each carried leaf is the FULL
    // T_leaf stream bytes so its hash + Merkle path reproduce round_roots[round];
    // the overlap with extract_out is checked byte-for-byte.
    uint64_t stream_offset{0};
    uint32_t first_leaf{0};
    std::vector<std::vector<uint8_t>> leaf_bytes;
    std::vector<RCMerkleProof> leaf_proofs;
};

/** One sampled layer: its Λ identity + the bounded set of opened output tiles. */
struct RCFreivaldsSampledLayer {
    uint32_t layer_index{0};   // index into the Λ enumeration (== wire index)
    uint32_t round{0};         // which round_root the openings target
    RCGkrLayerKind kind{};
    uint32_t m{0}, n{0}, k{0};
    std::vector<RCFreivaldsSampledTile> tiles;  // <= kRCFreivaldsSegOutTiles
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

// ---------------------------------------------------------------------------
// P2P RELAY of the sampled carrier — serialization (byte-exact round-trip) +
// bounded deserialization (untrusted input) + a process-local store keyed by
// block hash. This is the network-operability seam for the datacenter (profile
// 2) consensus path: a non-mining node that receives a profile-2 block over
// P2P has no local RCGkrProofV7, so CheckMatMulProofOfWork_RC validates against
// the RELAYED carrier fetched from this store (see pow.cpp). The carrier is a
// RELAY-ONLY object; it is NOT a consensus-serialized structure and its bytes
// never enter a block, a digest, or an FS seed. The consensus binding is the
// SEMANTIC one performed by VerifyEpisodeFreivaldsSampledCarrier (episode shape
// + digest→target + λ sampled layers), not this byte layout.
// ---------------------------------------------------------------------------

// DoS bounds for the untrusted wire form. The carrier arrives in a single P2P
// message capped by the net layer at MAX_PROTOCOL_MESSAGE_LENGTH (16 MB); the
// bound below is the module's own hard ceiling, re-checked on both serve and
// receive. With the v3 ANCHORED per-tile carrier the honest carrier fits UNDER this
// ceiling even at full PRODUCTION datacenter dims (design §2c binding relay
// constraint is resolved): per-sampled-layer relay is bounded by the per-tile
// anchored footprint (s_tile·(extract_out + A-row leaf + Merkle paths)), independent
// of the full m,n,k, so λ=512 sampled layers at d_model≥4096 serialize in
// ~single-digit MiB — the size that blew the full-operand carrier now fits. Oversize
// carriers are still rejected before parse.
inline constexpr size_t kRCFreivaldsCarrierMaxSerializedBytes = 12u * 1024u * 1024u;
/** Count caps (defense-in-depth alongside the byte ceiling): a violated cap
 *  aborts the deserialize, which net_processing scores as peer misbehavior. */
inline constexpr uint32_t kRCCarrierMaxRounds = 4096;          // round_seeds/round_roots
inline constexpr uint32_t kRCCarrierMaxSampledLayers = 4096;   // >= any λ we deploy (512)
inline constexpr uint32_t kRCCarrierMaxTilesPerLayer = 256;    // >= kRCFreivaldsSegOutTiles
inline constexpr uint32_t kRCCarrierMaxSegmentsPerTile = 4096; // >= s_ctr, and full-cover P
inline constexpr uint32_t kRCCarrierMaxLeavesPerTile = 4096;   // covering leaves per tile
inline constexpr uint32_t kRCCarrierMaxMerkleSiblings = 64;    // >= tree depth for any N
/** Per-vector element ceiling: no single carried vector may claim more elements
 *  than the whole-carrier byte ceiling could hold at 1 byte/elem. Combined with
 *  the running byte budget below this bounds allocation regardless of element
 *  width. */
inline constexpr uint64_t kRCCarrierMaxVecElems = kRCFreivaldsCarrierMaxSerializedBytes;

/** Serialize a carrier to a byte-exact wire form (miner/announce side). */
void SerializeRCFreivaldsCarrier(const RCFreivaldsSampledCarrier& carrier,
                                 std::vector<unsigned char>& out);

/**
 * BOUNDED deserialize from UNTRUSTED bytes. Enforces the hard byte ceiling
 * (kRCFreivaldsCarrierMaxSerializedBytes) BEFORE and DURING allocation via a
 * running budget, every count cap above, and rejects trailing data. Returns
 * false (why set) on any violation — it does NOT throw, so callers on the hot
 * path can branch; the P2P handler maps a false return to Misbehaving. Byte-
 * exact: DeserializeBounded(Serialize(c)) == c for any well-formed c whose wire
 * length is within the ceiling.
 */
[[nodiscard]] bool DeserializeRCFreivaldsCarrierBounded(Span<const unsigned char> in,
                                                        RCFreivaldsSampledCarrier& out,
                                                        std::string* why = nullptr);

// Process-local carrier store — LRU+TTL, same policy/limits as the V7 proof
// store (kRCGkrProofCacheMaxEntries / kRCGkrProofCacheTtlSeconds), independent
// mutex. Populated from the network (RCCARRIER receipt) and by the local miner
// (SolveMatMulV4RC) so CheckMatMulProofOfWork_RC always finds the carrier for a
// block it is about to validate. Keyed by block header hash.
void RCFreivaldsCarrierStorePut(const uint256& block_hash, RCFreivaldsSampledCarrier carrier);
[[nodiscard]] bool RCFreivaldsCarrierStoreGet(const uint256& block_hash,
                                              RCFreivaldsSampledCarrier& out);
[[nodiscard]] bool RCFreivaldsCarrierStoreHave(const uint256& block_hash);
void RCFreivaldsCarrierStoreClear();
[[nodiscard]] size_t RCFreivaldsCarrierStoreSizeForTest();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_SAMPLED_H
