// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Gate tests for the Poseidon2-Goldilocks algebraic hash `AlgHash`
// (matmul_v4_rc_alg_hash.{h,cpp}; spec §1 of scratchpad/stage-c-buildable-spec.md):
//   (a) gcd(7, p−1) = 1 (compile-time) and x ↦ x^7 injective on a random
//       sample (checked via the explicit inverse exponent e = 7^{-1} mod p−1);
//   (b) the frozen external matrix M_E is invertible and its 4×4 block M4 is
//       MDS (every square submatrix nonsingular);
//   (c) the generated internal matrix M_I = J + diag(μ) is invertible;
//   (d) the full permutation is a bijection: the explicit layer-by-layer
//       inverse composes to the identity on random states, both directions;
//   (e) frozen self-consistency vectors (spec §1.9), pinned from the first
//       reference run of the deterministic generator;
//   (f) the generated constant tables (96 RC_ext + 22 RC_int + 12 μ + node +
//       leaf domain seeds) pinned by checksum, plus μ/D/Le verbatim — any
//       change to SampleFp / the domain tag / SHA256d is caught immediately.

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_alg_hash_tests, BasicTestingSetup)

namespace {

using gf::Fp;

/** Deterministic PRNG (splitmix64) so failures are reproducible. */
uint64_t SplitMix64(uint64_t& state)
{
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

constexpr uint64_t ConstexprGcd(uint64_t a, uint64_t b)
{
    while (b != 0) {
        const uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

// (a) compile-time round-structure invariants: the S-box power is a unit mod
// p−1 (bijection) and the parameter set matches the analyzed instance.
static_assert(ConstexprGcd(7, gf::kP - 1) == 1, "x^7 must be a bijection on Fp");
static_assert(ah::kAlgHashT == 12 && ah::kAlgHashRate == 8 && ah::kAlgHashCapacity == 4);
static_assert(ah::kAlgHashFullRounds == 8 && ah::kAlgHashPartialRounds == 22);
static_assert(ah::kAlgHashRate + ah::kAlgHashCapacity == ah::kAlgHashT);
// Poseidon2-Goldilocks round-count gates at (p ≈ 2^64, d = 7, t = 12), 128-bit
// (spec §1.8): statistical R_F ≥ 6, interpolation R_P ≥ 22, Gröbner
// R_F + R_P ≥ 30. A future field/width change must re-derive these.
static_assert(ah::kAlgHashFullRounds >= 6);
static_assert(ah::kAlgHashPartialRounds >= 22);
static_assert(ah::kAlgHashFullRounds + ah::kAlgHashPartialRounds >= 30);

[[nodiscard]] Fp PowMod(Fp base, uint64_t exp)
{
    Fp result = 1;
    Fp b = gf::Canonical(base);
    while (exp > 0) {
        if (exp & 1u) result = gf::Mul(result, b);
        b = gf::Mul(b, b);
        exp >>= 1;
    }
    return result;
}

/** e = 7^{-1} mod (p−1) by extended Euclid (mirrors the module's derivation). */
[[nodiscard]] uint64_t InverseSboxExponent()
{
    const unsigned __int128 m = gf::kP - 1;
    __int128 old_r = 7, r = static_cast<__int128>(m);
    __int128 old_s = 1, s = 0;
    while (r != 0) {
        const __int128 q = old_r / r;
        const __int128 tr = old_r - q * r;
        old_r = r;
        r = tr;
        const __int128 ts = old_s - q * s;
        old_s = s;
        s = ts;
    }
    BOOST_REQUIRE(old_r == 1);
    if (old_s < 0) old_s += static_cast<__int128>(m);
    return static_cast<uint64_t>(old_s);
}

/** Rank of an n×n matrix over Fp by Gaussian elimination. */
[[nodiscard]] uint32_t MatrixRank(std::vector<std::vector<Fp>> m)
{
    const uint32_t n = static_cast<uint32_t>(m.size());
    uint32_t rank = 0;
    for (uint32_t col = 0; col < n && rank < n; ++col) {
        uint32_t pivot = rank;
        while (pivot < n && gf::Canonical(m[pivot][col]) == 0) ++pivot;
        if (pivot == n) continue;
        std::swap(m[pivot], m[rank]);
        const Fp inv = gf::Inv(m[rank][col]);
        for (uint32_t j = 0; j < n; ++j) m[rank][j] = gf::Mul(m[rank][j], inv);
        for (uint32_t row = 0; row < n; ++row) {
            if (row == rank || gf::Canonical(m[row][col]) == 0) continue;
            const Fp f = m[row][col];
            for (uint32_t j = 0; j < n; ++j) {
                m[row][j] = gf::Sub(m[row][j], gf::Mul(f, m[rank][j]));
            }
        }
        ++rank;
    }
    return rank;
}

/** Determinant over Fp by Gaussian elimination (small k×k). */
[[nodiscard]] Fp MatrixDet(std::vector<std::vector<Fp>> m)
{
    const uint32_t n = static_cast<uint32_t>(m.size());
    Fp det = 1;
    for (uint32_t col = 0; col < n; ++col) {
        uint32_t pivot = col;
        while (pivot < n && gf::Canonical(m[pivot][col]) == 0) ++pivot;
        if (pivot == n) return 0;
        if (pivot != col) {
            std::swap(m[pivot], m[col]);
            det = gf::Neg(det);
        }
        det = gf::Mul(det, m[col][col]);
        const Fp inv = gf::Inv(m[col][col]);
        for (uint32_t row = col + 1; row < n; ++row) {
            const Fp f = gf::Mul(m[row][col], inv);
            for (uint32_t j = col; j < n; ++j) {
                m[row][j] = gf::Sub(m[row][j], gf::Mul(f, m[col][j]));
            }
        }
    }
    return det;
}

/** 12×12 matrix of a linear layer from its action on the standard basis. */
template <typename Layer>
[[nodiscard]] std::vector<std::vector<Fp>> MatrixOfLayer(Layer layer)
{
    std::vector<std::vector<Fp>> m(ah::kAlgHashT, std::vector<Fp>(ah::kAlgHashT, 0));
    for (uint32_t j = 0; j < ah::kAlgHashT; ++j) {
        ah::State e{};
        e[j] = 1;
        layer(e);
        for (uint32_t i = 0; i < ah::kAlgHashT; ++i) m[i][j] = e[i];
    }
    return m;
}

} // namespace

// (a) runtime part: x ↦ x^7 is injective (its inverse power map undoes it on
// a random sample; injectivity of a map with a two-sided inverse is total).
BOOST_AUTO_TEST_CASE(alg_hash_sbox_bijective)
{
    const uint64_t e = InverseSboxExponent();
    // 7·e ≡ 1 (mod p−1)
    const unsigned __int128 prod = static_cast<unsigned __int128>(e) * 7u;
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(prod % (gf::kP - 1)), 1u);

    uint64_t seed = 0x5B0C7ULL;
    for (int i = 0; i < 256; ++i) {
        const Fp x = gf::FromU64(SplitMix64(seed));
        Fp x7 = gf::Mul(x, x);          // x^2
        const Fp x3 = gf::Mul(x7, x);   // x^3
        x7 = gf::Mul(x7, x7);           // x^4
        x7 = gf::Mul(x7, x3);           // x^7
        BOOST_CHECK_EQUAL(PowMod(x7, e), gf::Canonical(x));
    }
}

// (b) M_E invertible; the frozen 4×4 block M4 is MDS: every square submatrix
// (all 1×1, 2×2, 3×3, 4×4 minors) is nonsingular.
BOOST_AUTO_TEST_CASE(alg_hash_external_matrix_invertible_and_m4_mds)
{
    const auto me = MatrixOfLayer([](ah::State& s) { ah::ApplyExternalMatrix(s); });
    BOOST_CHECK_EQUAL(MatrixRank(me), ah::kAlgHashT);

    // FROZEN literal M4 (spec §1.3) — must match the implementation, so also
    // check ApplyExternalMatrix's top-left action is consistent with it.
    const Fp m4[4][4] = {{5, 7, 1, 3}, {4, 6, 1, 1}, {1, 3, 5, 7}, {1, 1, 4, 6}};
    // M_E block (0,0) = 2·M4 (circulant circ(2·M4, M4, M4)); blocks (0,1) and
    // (0,2) = M4.
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            BOOST_CHECK_EQUAL(gf::Canonical(me[i][j]), gf::Canonical(gf::Mul(2, m4[i][j])));
            BOOST_CHECK_EQUAL(gf::Canonical(me[i][4 + j]), gf::Canonical(m4[i][j]));
            BOOST_CHECK_EQUAL(gf::Canonical(me[i][8 + j]), gf::Canonical(m4[i][j]));
        }
    }

    // MDS: enumerate all square submatrices of M4 via row/column bitmasks of
    // equal popcount; every determinant must be nonzero.
    for (uint32_t rows = 1; rows < 16; ++rows) {
        for (uint32_t cols = 1; cols < 16; ++cols) {
            if (__builtin_popcount(rows) != __builtin_popcount(cols)) continue;
            std::vector<std::vector<Fp>> sub;
            for (int i = 0; i < 4; ++i) {
                if (!(rows & (1u << i))) continue;
                std::vector<Fp> r;
                for (int j = 0; j < 4; ++j) {
                    if (cols & (1u << j)) r.push_back(m4[i][j]);
                }
                sub.push_back(std::move(r));
            }
            BOOST_CHECK_MESSAGE(gf::Canonical(MatrixDet(sub)) != 0,
                                "singular M4 submatrix rows=" << rows << " cols=" << cols);
        }
    }
}

// (c) M_I = J + diag(μ) invertible; μ constraints hold.
BOOST_AUTO_TEST_CASE(alg_hash_internal_matrix_invertible)
{
    const auto mi = MatrixOfLayer([](ah::State& s) { ah::ApplyInternalMatrix(s); });
    BOOST_CHECK_EQUAL(MatrixRank(mi), ah::kAlgHashT);

    const ah::AlgHashConstants& c = ah::GetAlgHashConstants();
    for (uint32_t i = 0; i < ah::kAlgHashT; ++i) {
        BOOST_CHECK(gf::Canonical(c.mu[i]) != 0);
        BOOST_CHECK(gf::Canonical(c.mu[i]) != gf::kP - 1); // μ_i ≠ −1
        for (uint32_t j = 0; j < ah::kAlgHashT; ++j) {
            const Fp expect = (i == j) ? gf::Add(1, c.mu[i]) : 1; // J + diag(μ)
            BOOST_CHECK_EQUAL(gf::Canonical(mi[i][j]), gf::Canonical(expect));
        }
    }
}

// (d) the permutation is a bijection: the explicit inverse (layers undone in
// reverse; inverse S-box x ↦ x^{7^{-1} mod p−1}) composes to the identity in
// both directions on random states.
BOOST_AUTO_TEST_CASE(alg_hash_permutation_bijection)
{
    uint64_t seed = 0xA16BA5EDULL;
    for (int trial = 0; trial < 32; ++trial) {
        ah::State s{};
        for (auto& x : s) x = gf::FromU64(SplitMix64(seed));

        ah::State t = s;
        ah::Permute(t);
        ah::InversePermute(t);
        for (uint32_t i = 0; i < ah::kAlgHashT; ++i) {
            BOOST_CHECK_EQUAL(gf::Canonical(t[i]), gf::Canonical(s[i]));
        }

        t = s;
        ah::InversePermute(t);
        ah::Permute(t);
        for (uint32_t i = 0; i < ah::kAlgHashT; ++i) {
            BOOST_CHECK_EQUAL(gf::Canonical(t[i]), gf::Canonical(s[i]));
        }
    }
}

// (e) frozen self-consistency vectors (spec §1.9) — pinned from the first
// reference run; any change to constants, layers or round order breaks these.
BOOST_AUTO_TEST_CASE(alg_hash_frozen_vectors)
{
    static constexpr std::array<Fp, 12> kPermZero = {
        0x2287c4d3bf1f9fcfULL, 0x70a90902173f2d1cULL, 0xb331c17cce25bc3eULL, 0x27591cb7947b05f3ULL,
        0x073439f5d5fbea2eULL, 0x168ce8a263dfd4b7ULL, 0xeda90c02091a1f0aULL, 0x72e7851a82d0b051ULL,
        0xaaf3a754b4edd970ULL, 0x91034d60283ff45bULL, 0x6b0373a2b470b266ULL, 0x50f67bcd215fdbe1ULL,
    };
    static constexpr std::array<Fp, 12> kPermRamp = {
        0x5299bfc9eee3e7a7ULL, 0x533d45c648b8641dULL, 0xa59731920e50be6dULL, 0x05259779748aee6aULL,
        0xdfb695a78fe676edULL, 0x9b8091f3f7bda314ULL, 0x63759faf6bdd51ffULL, 0x1c2ebeb7c23b0b73ULL,
        0x2b571f2263cbd79cULL, 0x41b988c7ea375c3eULL, 0xe3937bdf275aa187ULL, 0xd65d44c6e711b816ULL,
    };
    static constexpr ah::Digest kCompress12345678 = {
        0x9650640f074fa21bULL, 0x3c7e128ad3b35178ULL, 0x2d8af8ffff445764ULL, 0x36935d8bd960b321ULL,
    };
    static constexpr ah::Digest kMerkleRoot4 = {
        0x9af44076577682fdULL, 0xe2d0c3a898c7c8b5ULL, 0x2e481a0b5e56215dULL, 0xf7f534fe852ccba3ULL,
    };

    ah::State z{};
    ah::Permute(z);
    for (uint32_t i = 0; i < ah::kAlgHashT; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(z[i]), kPermZero[i]);
    }

    ah::State r{};
    for (uint32_t i = 0; i < ah::kAlgHashT; ++i) r[i] = i;
    ah::Permute(r);
    for (uint32_t i = 0; i < ah::kAlgHashT; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(r[i]), kPermRamp[i]);
    }

    const ah::Digest c = ah::Compress({1, 2, 3, 4}, {5, 6, 7, 8});
    for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(c[i]), kCompress12345678[i]);
    }

    // Depth-2 tree over four Fp3 leaves (1,0,0)…(4,0,0), leaf index = position.
    std::array<ah::Digest, 4> h;
    for (uint32_t i = 0; i < 4; ++i) {
        h[i] = ah::LeafHash(gf::Fp3{i + 1, 0, 0}, i);
    }
    const ah::Digest root = ah::Compress(ah::Compress(h[0], h[1]), ah::Compress(h[2], h[3]));
    for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(root[i]), kMerkleRoot4[i]);
    }
}

// (f) generated constant tables pinned: checksums over all 132 derived values
// (96 RC_ext + 22 RC_int + 12 μ + D + Le), plus μ/D/Le verbatim. Any change to
// SampleFp, the domain tag or the byte-expansion breaks this immediately.
BOOST_AUTO_TEST_CASE(alg_hash_constant_table_checksum)
{
    static constexpr Fp kSumModP = 0x2fe74b3c58b1ae16ULL;
    static constexpr uint64_t kXor = 0x3d9daaca4557980cULL;
    static constexpr std::array<Fp, 12> kMu = {
        0xb15a4c581d0fe149ULL, 0xe6d63e29ccdee30eULL, 0xd2eba4563fe10a27ULL, 0x677d76bb3a6ff487ULL,
        0x8bf516a8317be27bULL, 0x34c6b8be23ba6deaULL, 0xd71479a76bab2933ULL, 0x31637db05a0165d7ULL,
        0xab8c37294501b6c5ULL, 0x8f0a7b6b1abbd065ULL, 0x7d2003f3ab8b57f2ULL, 0xf1b147cc7a0432a5ULL,
    };
    static constexpr Fp kNodeDomain = 0xb6c05c7c05fd9438ULL;
    static constexpr Fp kLeafDomain = 0xfc0e382189f5e13eULL;

    const ah::AlgHashConstants& c = ah::GetAlgHashConstants();
    Fp sum = 0;
    uint64_t x = 0;
    const auto acc = [&](Fp v) {
        sum = gf::Add(sum, v);
        x ^= gf::Canonical(v);
    };
    for (const auto& row : c.rc_ext) {
        for (const Fp v : row) acc(v);
    }
    for (const Fp v : c.rc_int) acc(v);
    for (const Fp v : c.mu) acc(v);
    acc(c.node_domain);
    acc(c.leaf_domain);

    BOOST_CHECK_EQUAL(gf::Canonical(sum), kSumModP);
    BOOST_CHECK_EQUAL(x, kXor);
    for (uint32_t i = 0; i < ah::kAlgHashT; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(c.mu[i]), kMu[i]);
    }
    BOOST_CHECK_EQUAL(gf::Canonical(c.node_domain), kNodeDomain);
    BOOST_CHECK_EQUAL(gf::Canonical(c.leaf_domain), kLeafDomain);
    BOOST_CHECK(kNodeDomain != kLeafDomain); // node/leaf domain separation
}

// Sponge sanity: 10*-padding separates trailing-zero inputs; the Fp3 sponge is
// the flattened-coordinate Fp sponge; LeafHashRow binds row values + index.
BOOST_AUTO_TEST_CASE(alg_hash_sponge_padding_and_fp3_embedding)
{
    const ah::Digest a = ah::SpongeHashFp({1, 2, 3});
    const ah::Digest b = ah::SpongeHashFp({1, 2, 3, 0});
    BOOST_CHECK(gf::Canonical(a[0]) != gf::Canonical(b[0]) ||
                gf::Canonical(a[1]) != gf::Canonical(b[1]));

    const std::vector<gf::Fp3> row = {gf::Fp3{1, 2, 3}, gf::Fp3{4, 5, 6}};
    const ah::Digest c = ah::SpongeHashFp3(row);
    const ah::Digest d = ah::SpongeHashFp({1, 2, 3, 4, 5, 6});
    for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(c[i]), gf::Canonical(d[i]));
    }

    const ah::Digest e = ah::LeafHashRow(row, 9);
    const ah::Digest f = ah::SpongeHashFp({1, 2, 3, 4, 5, 6, 9});
    for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
        BOOST_CHECK_EQUAL(gf::Canonical(e[i]), gf::Canonical(f[i]));
    }
    const ah::Digest g = ah::LeafHashRow(row, 10);
    BOOST_CHECK(gf::Canonical(e[0]) != gf::Canonical(g[0]) ||
                gf::Canonical(e[1]) != gf::Canonical(g[1]));
}

BOOST_AUTO_TEST_SUITE_END()
