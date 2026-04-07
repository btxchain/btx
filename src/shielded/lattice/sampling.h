// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_LATTICE_SAMPLING_H
#define BTX_SHIELDED_LATTICE_SAMPLING_H

#include <shielded/lattice/polyvec.h>

#include <random.h>
#include <span.h>

namespace shielded::lattice {

/** Uniform polynomial with coefficients in [0, q). */
[[nodiscard]] Poly256 SampleUniform(FastRandomContext& rng);

/** Small polynomial sampled from centered distribution in [-eta, eta]. */
[[nodiscard]] Poly256 SampleSmall(FastRandomContext& rng, int32_t eta = 2);

/** Uniform vector of polynomials. */
[[nodiscard]] PolyVec SampleUniformVec(FastRandomContext& rng, size_t len);

/** Small vector of polynomials. */
[[nodiscard]] PolyVec SampleSmallVec(FastRandomContext& rng, size_t len, int32_t eta = 2);

/** Deterministically expand one uniform polynomial from seed and nonce. */
[[nodiscard]] Poly256 ExpandUniformPoly(Span<const unsigned char> seed, uint32_t nonce);

/** Deterministically expand a uniform vector from seed and nonce base. */
[[nodiscard]] PolyVec ExpandUniformVec(Span<const unsigned char> seed, size_t len, uint32_t nonce_base = 0);

/** Deterministically sample MatRiCT+ challenge polynomial (fixed Hamming weight). */
[[nodiscard]] Poly256 SampleChallenge(Span<const unsigned char> transcript);

/** Sample a bounded polynomial with coefficients in [-bound, bound] using
 *  constant-time arithmetic (no rejection loops on secret-derived RNG state).
 *  Uses widened 64-bit multiply-and-reduce instead of randrange() retry loops. */
[[nodiscard]] Poly256 SampleBoundedPolyCT(FastRandomContext& rng, int32_t bound);

/** Sample a bounded PolyVec (MODULE_RANK polynomials) via SampleBoundedPolyCT. */
[[nodiscard]] PolyVec SampleBoundedVecCT(FastRandomContext& rng, size_t len, int32_t bound);

} // namespace shielded::lattice

#endif // BTX_SHIELDED_LATTICE_SAMPLING_H
