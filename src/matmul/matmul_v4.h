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

/** Commitment / sketch tile size b (§0.7, §E.1). m = n/b is the sketch
 *  dimension; b MUST divide n. */
inline constexpr uint32_t kTileB = 8;

/** Which of the two operand matrices a seed derives ('A' / 'B', §A.2). */
enum class Operand : uint8_t { A = 0x41, B = 0x42 };

/** Validate the (n, b) pair for v4: n > 0, b | n, and the exact-INT32
 *  accumulation bound (§B.4) holds. Returns m = n/b via `m_out` on success. */
[[nodiscard]] bool ValidateDims(uint32_t n, uint32_t b, uint32_t& m_out);

/** sigma = SHA256d(header) (§A.2/I7) -- reuses the v3 full-header rule via
 *  matmul::DeriveSigma so every consensus object binds nNonce64. */
[[nodiscard]] uint256 DeriveSigma(const CBlockHeader& header);

/** Derive the domain-separated XOF seed for operand A or B from the header
 *  (§A.2). Binds every header field (incl. nNonce64, hashPrevBlock) so operands
 *  are nonce-fresh and per-block memoryless (invariant I1). */
[[nodiscard]] uint256 DeriveOperandSeed(const CBlockHeader& header, Operand which);

/** Derive the nonce-fresh seeds for the sketch projectors U and V from sigma
 *  (invariant I7: template-constant projectors are forbidden). */
[[nodiscard]] std::pair<uint256, uint256> DeriveProjectorSeeds(const uint256& sigma);

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
 *  canonical F_q words (§E.1). U is m*n, V is n*m, C is n*n exact int32. */
[[nodiscard]] std::vector<Fq> ComputeSketch(const std::vector<int8_t>& U,
                                            const std::vector<int32_t>& C,
                                            const std::vector<int8_t>& V,
                                            uint32_t n, uint32_t m);

/** Serialize an m*m F_q sketch to canonical little-endian bytes (8 bytes/word,
 *  8*m^2 total -- 2 MiB at n=4096,b=8; §E.1). */
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
