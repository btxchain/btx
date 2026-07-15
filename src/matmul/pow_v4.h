// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_POW_V4_H
#define BTX_MATMUL_POW_V4_H

#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// Consensus-critical MatMul v4 proof-of-work API (design spec
// btx-matmul-v4-design-spec.md §0.7, §A, §D, §E). This is the surface the rest
// of the node integrates against: mining derives (digest, sketch payload) with
// ComputeDigest; validation replays the O(n^2) sketch-Freivalds check with
// VerifySketch. Neither function checks the difficulty target -- the caller
// compares `digest_out` against the target derived from nBits.
//
// LARGE-BATCH DETERMINISM: both entry points are pure integer arithmetic (no
// floating point anywhere on the consensus path, §B.6). A miner grinding a
// large nonce batch and a validator checking a single winning header MUST
// reproduce byte-identical digests and identical Freivalds outcomes across
// every backend (NVIDIA IMMA / AMD MFMA / Apple / AVX-512). Any backend that
// parallelizes must preserve the canonical element and serialization order;
// integer addition is associative, so tiling is permitted, but the committed
// sketch byte order (little-endian F_q words) is fixed.

namespace matmul_v4 {

/** Freivalds rounds R (§0.7-(2), §D.3): error <= 2/q per round in the sketch
 *  form, so R=3 gives <= 2^-180. Regtest uses 2 (caller passes `rounds`). */
static constexpr uint32_t kFreivaldsRounds = 3;

/** Commitment / sketch tile size b (§0.7, §E.1): m = n/b, payload 8*m^2. */
static constexpr uint32_t kTileB = 8;

/** Miner: compute the consensus digest and the sketch payload for `header` at
 *  dimension `n` (§A.4 Solve, §E.1).
 *
 *  Derives sigma and the nonce-fresh operands A,B (balanced-s8), forms the
 *  exact INT32 product C = A*B, projects it to the sketch Chat = U*C*V over
 *  q = 2^61-1, serializes Chat to `sketch_payload_out` (8*m^2 bytes ~ 2 MiB at
 *  n=4096,b=8), and sets `digest_out = H(sigma || Chat)`. `rounds` is accepted
 *  for API symmetry (the miner runs no Freivalds) and validated as > 0.
 *
 *  Returns false iff (n, kTileB) is invalid for v4 (n==0, b !| n, or the
 *  accumulation bound n*125^2 < 2^30 fails; §B.4). The caller then compares
 *  `digest_out` against the difficulty target. */
[[nodiscard]] bool ComputeDigest(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                 uint256& digest_out, std::vector<unsigned char>& sketch_payload_out);

/** Verifier: O(n^2) consensus check (§0.7-(1)/§D/§E.2). Regenerates A,B from the
 *  header seeds, runs `rounds` sketch-Freivalds rounds over q = 2^61-1 against
 *  `sketch_payload` using matrix-vector products A*(B*r) (never forming C),
 *  recomputes the digest from the payload, and returns true iff every round is
 *  consistent AND the recomputed digest equals `header.matmul_digest`.
 *
 *  `digest_out` receives the recomputed digest (so the caller may re-check it
 *  against the target). This routine does NOT check the target. Cost is
 *  O(rounds * n^2) with no O(n^3) step anywhere. */
[[nodiscard]] bool VerifySketch(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                const std::vector<unsigned char>& sketch_payload, uint256& digest_out);

/** True iff `sketch_payload` (as shipped) hashes to `header.matmul_digest`, i.e.
 *  the body is the committed sketch for this header. Runs no Freivalds and no
 *  target check -- it only answers "is this the payload the header commits to?".
 *
 *  Used to classify a failed v4 block: if this returns false the failure is a
 *  BODY MUTATION (a different, correct payload for this same header hash exists,
 *  so the block hash must NOT be permanently invalidated -- otherwise an
 *  attacker could poison a valid header's hash by relaying a corrupted-payload
 *  copy first). If it returns true, any remaining failure (Freivalds mismatch or
 *  digest-over-target) is a header-level CONSENSUS fault and is permanent. */
[[nodiscard]] bool PayloadMatchesCommitment(const CBlockHeader& header,
                                            const std::vector<unsigned char>& sketch_payload);

} // namespace matmul_v4

#endif // BTX_MATMUL_POW_V4_H
