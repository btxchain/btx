// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_H
#define BTX_MATMUL_MATMUL_V4_H

#include <matmul/int8_field.h>
#include <uint256.h>

#include <cstdint>
#include <utility>
#include <vector>

class CBlockHeader;

// Core MatMul v4 primitives: seed->operand expansion, the exact s8xs8->s32
// dense product, the compressed sketch commitment Chat = U*C*V over F_q, the
// digest H(sigma || Chat), and the O(n^2) sketch-Freivalds verifier.
//
// See btx-matmul-v4-design-spec.md §A (algorithm), §B (INT8 field), §D
// (Freivalds over q = 2^61-1), §E (sketch payload). The consensus entry points
// are in pow_v4.h; this header exposes the reusable building blocks so the
// miner (ComputeDigest) and verifier (VerifySketch) share one derivation path.
//
// LARGE-BATCH DETERMINISM NOTE: every routine here is pure integer arithmetic
// with a fixed, sequential accumulation order. Two nodes -- or a miner grinding
// a large nonce batch and a verifier checking one winner -- MUST reproduce
// identical bytes. Callers that parallelize expansion or the product MUST
// preserve this canonical element order (index-major A/B/U/V, row-major C) and
// MUST NOT introduce floating point; integer add is associative so tiling is
// permitted, but the committed serialization order (SerializeSketch) is fixed.

namespace matmul::v4 {

using int8_field::Fq;

/** Commitment / sketch tile size b (§0.7, §E.1, §K.2b). m = n/b is the sketch
 *  dimension; b MUST divide n.
 *
 *  Revised 8 -> 4 (v4.1 batched-sketch profile, PR #89 wall-time fix): at b=8
 *  the reviewer MEASURED the workload consumer-favoring (H100/RTX 5090 = 0.40x
 *  nonce-throughput at n=8192) — the skinny per-nonce GEMMs plus the SHA/
 *  memory-bound operand generation do not exercise a datacenter part's dense-
 *  GEMM strength. b=4 doubles m, raising the per-nonce tensor volume to
 *  ~1.25*n^3 marginal MACs (B*V + the C-13 limb combine; U*A is template-
 *  amortized under I1'), and the batched miner (matmul_v4_batch.h) fuses the
 *  per-nonce combines into one large dense GEMM. Whether this restores the
 *  datacenter ordering is a DESIGN HYPOTHESIS that MUST be confirmed on real
 *  H100/B200 silicon with matmul_v4_stage_bench (§K.2b) — the two previous
 *  model-based estimates were both wrong. Payload is 8*(n/b)^2 = 8 MiB at
 *  n=4096 — still inside the existing 16 MiB message limit. If n is ever
 *  retargeted to 8192, b MUST be retargeted to 8 so m stays 1024 and the
 *  payload stays 8 MiB (§E.1). Keep in sync with
 *  Consensus::Params::nMatMulV4TranscriptBlockSize and matmul_v4::kTileB. */
inline constexpr uint32_t kTileB = 4;

/** Limb decomposition of the combine stage (Appendix C-13, §K.2b): every
 *  exact-int32 entry of P = U*A and Q = B*V is split into kCombineLimbs
 *  balanced base-2^7 digits in [-64, 63], so the m*m*n combine runs as
 *  kCombineLimbs^2 native s8xs8->s32 tensor GEMMs plus one O(m^2) mod-q
 *  recombine on the integer ALU. 4 limbs cover |P| <= n*125^2 = 15,625*n for
 *  every n <= 8589, i.e. the whole 4096..8192 dimension window (see
 *  CheckCombineLimbBound). */
inline constexpr uint32_t kCombineLimbs = 4;
inline constexpr int32_t kCombineLimbBase = 128; // digits in [-64, 63]

/** Which of the two operand matrices a seed derives ('A' / 'B', §A.2). */
enum class Operand : uint8_t { A = 0x41, B = 0x42 };

/** Validate the (n, b) pair for v4: n > 0, b | n, and the exact-INT32
 *  accumulation bound (§B.4) holds. Returns m = n/b via `m_out` on success. */
[[nodiscard]] bool ValidateDims(uint32_t n, uint32_t b, uint32_t& m_out);

/** sigma = SHA256d(header) (§A.2/I1') -- reuses the v3 full-header rule via
 *  matmul::DeriveSigma so every consensus object binds nNonce64. sigma stays
 *  NONCE-FRESH in v4.1: the digest H(sigma || Chat) and every Fiat-Shamir
 *  Freivalds challenge bind the nonce through it. */
[[nodiscard]] uint256 DeriveSigma(const CBlockHeader& header);

/** TEMPLATE hash (§A.2 v4.1): the canonical matmul header hash computed over a
 *  copy of the header with every nonce-dependent field zeroed — nNonce64,
 *  nNonce, AND the seed_a/seed_b header fields (which are themselves
 *  nonce-derived commitments under the §H.4 seed rule, so leaving them in
 *  would fold the nonce right back into the "template" projection; they are
 *  redundant here because consensus separately pins them to their §H.4
 *  derivation). What remains bound: nVersion, hashPrevBlock, hashMerkleRoot,
 *  nTime, nBits, matmul_dim. hashPrevBlock transitively binds height and
 *  parent-MTP, so nothing template-scoped is computable before the parent
 *  block exists (the I1 memorylessness corollary survives at template
 *  granularity). Constant across a miner's whole nonce sweep of one
 *  template. */
[[nodiscard]] uint256 ComputeTemplateHash(const CBlockHeader& header);

/** Derive the domain-separated XOF seed for operand A or B from the header
 *  (§A.2, revised by the v4.1 batched-sketch profile — §K.2b, invariant I1'):
 *
 *   - Operand B binds EVERY header field including nNonce64: B is nonce-fresh,
 *     so the per-nonce marginal work (expand B, B*V, the combine, the digest)
 *     is unavoidable per candidate and is what difficulty prices (I1').
 *   - Operand A binds the TEMPLATE hash only (ComputeTemplateHash): A is
 *     template-scoped — constant across a miner's nonce sweep, recomputed
 *     whenever hashPrevBlock / hashMerkleRoot / nTime / nBits change. Together
 *     with the template-scoped projectors (DeriveProjectorSeeds) this lets a
 *     miner compute P = U*A ONCE per template and batch many nonces' combines
 *     into one large dense GEMM P * [B_1*V | ... | B_Q*V] (§K.2b,
 *     matmul_v4_batch.h). This DELIBERATELY relaxes v4.0's I1 "both operands
 *     nonce-fresh" — see I1' in the design spec §C for the security argument
 *     and its needs-external-review status. A remains parent-bound, so no
 *     pre-mining before the template exists. */
[[nodiscard]] uint256 DeriveOperandSeed(const CBlockHeader& header, Operand which);

/** Derive the seeds for the sketch projectors U and V (§A.2 v4.1, invariant
 *  I1' — supersedes v4.0's I7): TEMPLATE-scoped, from ComputeTemplateHash
 *  under distinct U/V domain tags. U and V are constant across a miner's
 *  nonce sweep (enabling the §K.2b amortization of P = U*A and the shared V
 *  in B_i*V), while remaining parent/template-bound (no precomputation before
 *  the template exists) and identical for every miner (no asymmetric
 *  advantage). Verification soundness is untouched: the Freivalds challenges
 *  remain nonce-fresh, derived from H(sigma || H(payload)) (Fiat-Shamir). */
[[nodiscard]] std::pair<uint256, uint256> DeriveProjectorSeeds(const CBlockHeader& header);

/** Expand a seed into an n*n row-major balanced-s8 operand matrix (§A.2/§B). */
[[nodiscard]] std::vector<int8_t> ExpandOperand(const uint256& seed, uint32_t n);

/** Expand a seed into a rows*cols row-major balanced-s8 projector (U is m*n,
 *  V is n*m; §0.7 "balanced s8" U,V, §E.1). */
[[nodiscard]] std::vector<int8_t> ExpandProjector(const uint256& seed, uint32_t rows, uint32_t cols);

/** Exact dense s8xs8->s32 product C = A*B, returned row-major as exact int32
 *  (§A.3/§B.4). `A`/`B` are n*n row-major balanced-s8; the caller MUST have
 *  validated the accumulation bound. This is the honest reference miner path;
 *  it is Theta(n^3). */
[[nodiscard]] std::vector<int32_t> ComputeExactProduct(const std::vector<int8_t>& A,
                                                       const std::vector<int8_t>& B,
                                                       uint32_t n);

/** Compute the sketch commitment Chat = U*C*V in F_q, returned row-major as m*m
 *  canonical F_q words (§E.1). U is m*n, V is n*m, C is n*n exact int32. This is
 *  the full-C reference path (Theta(n^3) via ComputeExactProduct); it is the
 *  consensus definition of the sketch and the verifier-side reference. */
[[nodiscard]] std::vector<Fq> ComputeSketch(const std::vector<int8_t>& U,
                                            const std::vector<int32_t>& C,
                                            const std::vector<int8_t>& V,
                                            uint32_t n, uint32_t m);

/** Optimal miner sketch (§E.3): compute Chat = (U*A)(B*V) mod q DIRECTLY, never
 *  forming the n*n product C. U is m*n, A/B are n*n, V is n*m, all balanced-s8.
 *
 *  P = U*A (m*n) and Q = B*V (n*m) are exact s8xs8->s32 integer GEMMs -- each
 *  entry is a length-n balanced-s8 dot, |.| <= n*125^2 < 2^30, so it fits the
 *  same exact INT32 accumulator as C (CheckAccumulationBound, §B.4). The m*m
 *  combine Chat[a][c] = (sum_k P[a][k]*Q[k][c]) mod q reproduces the int8_field
 *  FqFromInt32/FqMul/FqAdd path bit-for-bit.
 *
 *  BYTE-IDENTICAL to ComputeSketch(U, A*B, V): by integer-matrix associativity
 *  (U*A)(B*V) == U*(A*B)*V == U*C*V as EXACT integer matrices, so every m*m
 *  entry is the same integer and thus the same UNIQUE canonical F_q residue in
 *  [0, q). Identical residues => identical SerializeSketch bytes => identical
 *  digest. Cost is ~2*n^2*m MACs instead of Theta(n^3). */
[[nodiscard]] std::vector<Fq> ComputeSketchOptimal(const std::vector<int8_t>& U,
                                                   const std::vector<int8_t>& A,
                                                   const std::vector<int8_t>& B,
                                                   const std::vector<int8_t>& V,
                                                   uint32_t n, uint32_t m);

/** P = U*A, exact s8xs8->s32, m*n row-major (§E.3). Each entry is a length-n
 *  balanced-s8 dot, |.| <= 15,625*n < 2^30, exact in int32. Exposed separately
 *  so the batched miner (matmul_v4_batch.h) can reuse a template-cached A. */
[[nodiscard]] std::vector<int32_t> ComputeProjectedLeft(const std::vector<int8_t>& U,
                                                        const std::vector<int8_t>& A,
                                                        uint32_t n, uint32_t m);

/** Q = B*V, exact s8xs8->s32, n*m row-major (§E.3). Same bound as P. */
[[nodiscard]] std::vector<int32_t> ComputeProjectedRight(const std::vector<int8_t>& B,
                                                         const std::vector<int8_t>& V,
                                                         uint32_t n, uint32_t m);

/** True iff the 4-limb balanced base-2^7 decomposition covers every possible
 *  P = U*A / Q = B*V entry at dimension n: 15,625*n < kCombineLimbBase^4 / 2.
 *  Holds for all n <= 8589, i.e. the whole v4 dimension window. */
[[nodiscard]] bool CheckCombineLimbBound(uint32_t n);

/** Combine stage, direct integer-ALU reference (§E.3): Chat = P*Q mod q, where
 *  P = U*A is m*n and Q = B*V is n*m, both exact int32 (|.| <= 15,625*n).
 *  Row-major m*m canonical F_q output. This is the consensus semantics of the
 *  combine; ComputeCombineLimbTensor MUST match it byte-for-byte. */
[[nodiscard]] std::vector<Fq> ComputeCombineModQ(const std::vector<int32_t>& P,
                                                 const std::vector<int32_t>& Q,
                                                 uint32_t n, uint32_t m);

/** Combine stage, tensor-shaped limb path (Appendix C-13): decompose P and Q
 *  entrywise into kCombineLimbs balanced base-2^7 digits (each digit matrix a
 *  valid s8 operand), compute the kCombineLimbs^2 = 16 limb-pair m*m products
 *  with exact s8xs8->s32 accumulation (each fits int32: n*64^2 < 2^31 for all
 *  header n), then recombine S_ij with the shifted mod-q fold
 *      Chat = sum_ij 2^(7(i+j)) * S_ij  (mod q)
 *  in O(m^2) on the integer ALU. BYTE-IDENTICAL to ComputeCombineModQ: the 16
 *  limb-pair sums recompose the exact integer sum_k P[a][k]*Q[k][c] termwise
 *  mod q, and canonical residues are unique. This is the CPU reference for the
 *  GPU backends' tensor-core combine (the 16 limb-pair GEMMs are native IMMA /
 *  MFMA / TensorOps shapes m*m*n). */
[[nodiscard]] std::vector<Fq> ComputeCombineLimbTensor(const std::vector<int32_t>& P,
                                                       const std::vector<int32_t>& Q,
                                                       uint32_t n, uint32_t m);

/** Cross-nonce STACKED combine (§K.2b batched-sketch miner): identical
 *  semantics to ComputeCombineLimbTensor, but `Qstack` is n x q_cols row-major
 *  with q_cols = Q*m — the horizontal stack [B_1*V | B_2*V | ... | B_Q*V] of Q
 *  nonces' right factors — and the output is m x q_cols row-major. This is the
 *  ONE LARGE DENSE GEMM P * Qstack (m x n by n x Q*m) that the batched miner
 *  evaluates per nonce window; column block i (columns [i*m, (i+1)*m)) is
 *  BYTE-IDENTICAL to ComputeCombineLimbTensor(P, Q_i, n, m) because every
 *  output entry depends only on its own P row and Qstack column and the limb
 *  decomposition is entrywise (integer arithmetic, exact). q_cols MUST be a
 *  positive multiple of m. */
[[nodiscard]] std::vector<Fq> ComputeCombineLimbTensorStacked(const std::vector<int32_t>& P,
                                                              const std::vector<int32_t>& Qstack,
                                                              uint32_t n, uint32_t m,
                                                              uint32_t q_cols);

/** Serialize an m*m F_q sketch to canonical little-endian bytes (8 bytes/word,
 *  8*m^2 total -- 8 MiB at n=4096,b=4; §E.1). */
[[nodiscard]] std::vector<unsigned char> SerializeSketch(const std::vector<Fq>& sketch);

/** Parse and range-check a serialized sketch payload of m*m words. Returns
 *  false if the length is wrong or any word is non-canonical (>= q), mirroring
 *  v3's payload canonicality check (§D.3-(1), cf. src/pow.cpp:2867). */
[[nodiscard]] bool ParseSketch(const std::vector<unsigned char>& payload, uint32_t m,
                               std::vector<Fq>& sketch_out);

/** Digest matmul_digest = H(sigma || Chat) over the serialized sketch payload
 *  (§E.1/§0.7-(3)). Domain-separated SHA256d. */
[[nodiscard]] uint256 ComputeSketchDigest(const uint256& sigma,
                                          const std::vector<unsigned char>& payload);

/** Run `rounds` sketch-Freivalds checks over F_q (§E.2). For each round the
 *  challenge (x, y) in F_q^m is derived from H(sigma || H(payload)) (Fiat-Shamir,
 *  binds the payload, invariant I7) and the bilinear identity
 *
 *      x^T Chat y  ==  (U^T x)^T A (B (V y))
 *
 *  is checked. The right side is two dense O(n^2) matvecs A*(B*(V*y)) plus O(nm)
 *  projections and NEVER forms C; the left side is O(m^2). Per-round error
 *  <= 2/q (total degree 2, Schwartz-Zippel), so R=3 gives <= 2^-180 (§E.2).
 *  Returns true iff every round matches. O(rounds * n^2). */
[[nodiscard]] bool SketchFreivalds(const std::vector<int8_t>& A,
                                   const std::vector<int8_t>& B,
                                   const std::vector<int8_t>& U,
                                   const std::vector<int8_t>& V,
                                   const std::vector<Fq>& sketch,
                                   const uint256& sigma,
                                   const std::vector<unsigned char>& payload,
                                   uint32_t n, uint32_t m, uint32_t rounds);

} // namespace matmul::v4

#endif // BTX_MATMUL_MATMUL_V4_H
