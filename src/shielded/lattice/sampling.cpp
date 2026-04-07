// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/lattice/sampling.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <util/fastrange.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace shielded::lattice {
namespace {

[[nodiscard]] uint256 DeriveSeed(Span<const unsigned char> input, uint32_t nonce, const char* domain)
{
    uint256 out;
    unsigned char nonce_le[4];
    WriteLE32(nonce_le, nonce);
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(domain), std::strlen(domain))
        .Write(input.data(), input.size())
        .Write(nonce_le, sizeof(nonce_le))
        .Finalize(out.begin());
    return out;
}

} // namespace

Poly256 SampleUniform(FastRandomContext& rng)
{
    Poly256 out;
    for (size_t i = 0; i < POLY_N; ++i) {
        out.coeffs[i] = static_cast<int32_t>(rng.randrange(POLY_Q));
    }
    return out;
}

Poly256 SampleSmall(FastRandomContext& rng, int32_t eta)
{
    // NOTE: This function is consensus-critical (used in DeriveInputSecretFromNote).
    // Do NOT change the RNG consumption pattern as it would break secret derivation.
    // The randrange() call here operates on a public bound (eta+1 ≤ 3) and the
    // rejection loop timing depends only on RNG output, not on secret values.
    Poly256 out;
    for (size_t i = 0; i < POLY_N; ++i) {
        const int32_t a = static_cast<int32_t>(rng.randrange(static_cast<uint32_t>(eta + 1)));
        const int32_t b = static_cast<int32_t>(rng.randrange(static_cast<uint32_t>(eta + 1)));
        out.coeffs[i] = a - b;
    }
    return out;
}

PolyVec SampleUniformVec(FastRandomContext& rng, size_t len)
{
    PolyVec out(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = SampleUniform(rng);
    }
    return out;
}

PolyVec SampleSmallVec(FastRandomContext& rng, size_t len, int32_t eta)
{
    PolyVec out(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = SampleSmall(rng, eta);
    }
    return out;
}

Poly256 ExpandUniformPoly(Span<const unsigned char> seed, uint32_t nonce)
{
    const uint256 expanded = DeriveSeed(seed, nonce, "BTX_MatRiCT_UniformPoly_V1");
    FastRandomContext rng(expanded);
    return SampleUniform(rng);
}

PolyVec ExpandUniformVec(Span<const unsigned char> seed, size_t len, uint32_t nonce_base)
{
    PolyVec out(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = ExpandUniformPoly(seed, nonce_base + static_cast<uint32_t>(i));
    }
    return out;
}

Poly256 SampleChallenge(Span<const unsigned char> transcript)
{
    const uint256 expanded = DeriveSeed(transcript, 0, "BTX_MatRiCT_Challenge_V2");
    FastRandomContext rng(expanded);

    // Fisher-Yates partial shuffle: constant-time position selection
    // to avoid variable-iteration retry-on-collision.
    std::array<size_t, POLY_N> indices;
    for (size_t i = 0; i < POLY_N; ++i) indices[i] = i;

    Poly256 challenge{};
    for (size_t i = 0; i < static_cast<size_t>(BETA_CHALLENGE); ++i) {
        const size_t j = i + rng.randrange(POLY_N - i);
        std::swap(indices[i], indices[j]);
        challenge.coeffs[indices[i]] = rng.randbool() ? 1 : -1;
    }
    return challenge;
}

Poly256 SampleBoundedPolyCT(FastRandomContext& rng, int32_t bound)
{
    Poly256 out{};
    if (bound <= 0) return out;
    // Use widened 64-bit multiplication to map a uniform uint64 into [-bound, bound]
    // without any rejection loops.  The modular bias is negligible:
    //   span = 2*bound+1 <= 2*131072+1 = 262145
    //   bias <= span / 2^64 ≈ 2^{-46}  — well below cryptographic thresholds.
    const uint64_t span = static_cast<uint64_t>(bound) * 2U + 1U;
    for (size_t i = 0; i < POLY_N; ++i) {
        const uint64_t r = rng.rand64();
        // Map r ∈ [0, 2^64) → [0, span) via widened multiply high-word.
        // result = (r * span) >> 64, computed via __uint128_t.
        const uint64_t mapped = FastRange64(r, span);
        out.coeffs[i] = static_cast<int32_t>(mapped) - bound;
    }
    return out;
}

PolyVec SampleBoundedVecCT(FastRandomContext& rng, size_t len, int32_t bound)
{
    PolyVec out(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = SampleBoundedPolyCT(rng, bound);
    }
    return out;
}

} // namespace shielded::lattice
