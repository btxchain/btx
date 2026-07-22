// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Finite-field algebra checks for Fp3 = Fp[x]/(x^3 - 2) over Goldilocks
// (matmul_v4_rc_gkr_field_ext3.h):
//   - W3 = 2 is a verified non-cube (irreducibility witness for x^3 - W3);
//   - field axioms on deterministic pseudo-random elements (associativity,
//     commutativity, distributivity, a * Inv(a) = 1 for a != 0);
//   - Frobenius consistency: a^p by square-and-multiply exponentiation agrees
//     with the coordinate map (a0, w a1, w^2 a2), and a^{p^3} = a;
//   - Mul matches a schoolbook-then-reduce reference;
//   - challenge derivation consumes 24 bytes into (c0, c1, c2) mod p.

#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>

namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_gkr_field_ext3_tests, BasicTestingSetup)

namespace {

/** Deterministic PRNG (splitmix64) so failures are reproducible. */
uint64_t SplitMix64(uint64_t& state)
{
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

gf::Fp3 RandomFp3(uint64_t& state)
{
    return gf::Fp3{gf::FromU64(SplitMix64(state)), gf::FromU64(SplitMix64(state)),
                   gf::FromU64(SplitMix64(state))};
}

/** Base-field square-and-multiply a^e mod p. */
gf::Fp PowFp(gf::Fp a, uint64_t e)
{
    gf::Fp base = gf::Canonical(a);
    gf::Fp result = 1;
    while (e > 0) {
        if (e & 1u) result = gf::Mul(result, base);
        base = gf::Mul(base, base);
        e >>= 1;
    }
    return result;
}

/** Extension-field square-and-multiply a^e (e a u64, enough for e = p). */
gf::Fp3 PowFp3(const gf::Fp3& a, uint64_t e)
{
    gf::Fp3 base = a;
    gf::Fp3 result = gf::Fp3::One();
    while (e > 0) {
        if (e & 1u) result = gf::Mul(result, base);
        base = gf::Mul(base, base);
        e >>= 1;
    }
    return result;
}

/** Reference multiply: schoolbook degrees 0..4, then fold by x^3 = W3. */
gf::Fp3 SchoolbookMul(const gf::Fp3& a, const gf::Fp3& b)
{
    const gf::Fp av[3] = {a.c0, a.c1, a.c2};
    const gf::Fp bv[3] = {b.c0, b.c1, b.c2};
    gf::Fp d[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 3; ++j) {
            d[i + j] = gf::Add(d[i + j], gf::Mul(av[i], bv[j]));
        }
    }
    // x^3 -> W3, x^4 -> W3 x.
    return gf::Fp3{gf::Add(d[0], gf::Mul(gf::kFp3W, d[3])),
                   gf::Add(d[1], gf::Mul(gf::kFp3W, d[4])), d[2]};
}

} // namespace

BOOST_AUTO_TEST_CASE(gkr_field_ext3_w3_is_noncube)
{
    // p - 1 = 2^32 (2^32 - 1) with 3 | (2^32 - 1); (p - 1) / 3 fits a u64.
    const uint64_t exp_third = (gf::kP - 1) / 3;
    BOOST_CHECK_EQUAL(exp_third * 3, gf::kP - 1);

    // W3 = 2 is a non-cube: 2^((p-1)/3) != 1, hence x^3 - 2 is irreducible.
    const gf::Fp c = PowFp(gf::kFp3W, exp_third);
    BOOST_CHECK(c != 1);

    // The cube-residue symbol of a non-cube is a primitive cube root of
    // unity; it is exactly the Frobenius constant omega documented in the
    // header, and omega^2 matches too.
    BOOST_CHECK_EQUAL(c, gf::kFp3Omega);
    BOOST_CHECK_EQUAL(gf::Mul(c, c), gf::kFp3Omega2);
    BOOST_CHECK_EQUAL(gf::Mul(gf::Mul(c, c), c), 1U);

    // Sanity: an actual cube (5 = smallest cube > 1) passes the cube test.
    BOOST_CHECK_EQUAL(PowFp(5, exp_third), 1U);
}

BOOST_AUTO_TEST_CASE(gkr_field_ext3_field_axioms_random)
{
    uint64_t st = 0xB7C3'0FA3'11D2'96E4ULL;
    const gf::Fp3 zero = gf::Fp3::Zero();
    const gf::Fp3 one = gf::Fp3::One();

    for (int iter = 0; iter < 64; ++iter) {
        const gf::Fp3 a = RandomFp3(st);
        const gf::Fp3 b = RandomFp3(st);
        const gf::Fp3 c = RandomFp3(st);

        // Additive group.
        BOOST_CHECK(gf::Eq(gf::Add(a, b), gf::Add(b, a)));
        BOOST_CHECK(gf::Eq(gf::Add(gf::Add(a, b), c), gf::Add(a, gf::Add(b, c))));
        BOOST_CHECK(gf::Eq(gf::Add(a, zero), a));
        BOOST_CHECK(gf::Eq(gf::Add(a, gf::Neg(a)), zero));
        BOOST_CHECK(gf::Eq(gf::Sub(a, b), gf::Add(a, gf::Neg(b))));

        // Multiplicative monoid.
        BOOST_CHECK(gf::Eq(gf::Mul(a, b), gf::Mul(b, a)));
        BOOST_CHECK(gf::Eq(gf::Mul(gf::Mul(a, b), c), gf::Mul(a, gf::Mul(b, c))));
        BOOST_CHECK(gf::Eq(gf::Mul(a, one), a));
        BOOST_CHECK(gf::Eq(gf::Mul(a, zero), zero));

        // Distributivity.
        BOOST_CHECK(gf::Eq(gf::Mul(a, gf::Add(b, c)),
                           gf::Add(gf::Mul(a, b), gf::Mul(a, c))));

        // Multiplicative inverse (random elements are nonzero w.h.p.; guard).
        if (!gf::IsZero(a)) {
            BOOST_CHECK(gf::Eq(gf::Mul(a, gf::Inv(a)), one));
            BOOST_CHECK(gf::Eq(gf::Div(a, a), one));
        }
        if (!gf::IsZero(b)) {
            BOOST_CHECK(gf::Eq(gf::Mul(gf::Div(a, b), b), a));
        }
    }

    // Inv(0) = 0: precondition-style, non-fatal (matches the Fp2 module).
    BOOST_CHECK(gf::Eq(gf::Inv(zero), zero));

    // Base-field embedding is a ring homomorphism on a sample.
    const gf::Fp3 e7 = gf::FromU64_3(7);
    const gf::Fp3 e9 = gf::FromU64_3(9);
    BOOST_CHECK(gf::Eq(gf::Mul(e7, e9), gf::FromU64_3(63)));
    BOOST_CHECK(gf::Eq(gf::FromSigned3(-1), gf::Neg(one)));
}

BOOST_AUTO_TEST_CASE(gkr_field_ext3_frobenius_consistency)
{
    uint64_t st = 0x0D15'EA5E'CAFE'F00DULL;
    for (int iter = 0; iter < 16; ++iter) {
        const gf::Fp3 a = RandomFp3(st);

        // a^p by generic exponentiation (kP fits a u64) vs the coordinate map.
        const gf::Fp3 frob_pow = PowFp3(a, gf::kP);
        const gf::Fp3 frob_map = gf::Frobenius(a);
        BOOST_CHECK(gf::Eq(frob_pow, frob_map));

        // Frob^2 two ways, and Frob^3 = identity (a^{p^3} = a).
        BOOST_CHECK(gf::Eq(gf::Frobenius(gf::Frobenius(a)), gf::Frobenius2(a)));
        BOOST_CHECK(gf::Eq(gf::Frobenius(gf::Frobenius2(a)), a));

        // The norm a * a^p * a^{p^2} lands in the base field (c1 = c2 = 0),
        // which is the fact the Inv() derivation rests on.
        const gf::Fp3 norm = gf::Mul(a, gf::Mul(frob_map, gf::Frobenius2(a)));
        BOOST_CHECK_EQUAL(gf::Canonical(norm.c1), 0U);
        BOOST_CHECK_EQUAL(gf::Canonical(norm.c2), 0U);

        // Frobenius fixes exactly the base-field embedding.
        const gf::Fp3 base = gf::FromU64_3(SplitMix64(st));
        BOOST_CHECK(gf::Eq(gf::Frobenius(base), base));
    }
}

BOOST_AUTO_TEST_CASE(gkr_field_ext3_mul_matches_schoolbook)
{
    uint64_t st = 0x5EED'5EED'5EED'5EEDULL;
    for (int iter = 0; iter < 64; ++iter) {
        const gf::Fp3 a = RandomFp3(st);
        const gf::Fp3 b = RandomFp3(st);
        BOOST_CHECK(gf::Eq(gf::Mul(a, b), SchoolbookMul(a, b)));
    }
    // Deterministic corner cases: coefficients at/near p wrap correctly.
    const gf::Fp3 edge{gf::kP - 1, gf::kP - 1, gf::kP - 1};
    BOOST_CHECK(gf::Eq(gf::Mul(edge, edge), SchoolbookMul(edge, edge)));
    const gf::Fp3 x{0, 1, 0};
    const gf::Fp3 x2{0, 0, 1};
    // x * x^2 = x^3 = W3.
    BOOST_CHECK(gf::Eq(gf::Mul(x, x2), gf::FromU64_3(gf::kFp3W)));
    // x^2 * x^2 = x^4 = W3 x.
    BOOST_CHECK(gf::Eq(gf::Mul(x2, x2), gf::Fp3{0, gf::kFp3W, 0}));
}

BOOST_AUTO_TEST_CASE(gkr_field_ext3_challenge_bytes)
{
    // 24 FS bytes -> (c0, c1, c2), each 8 LE bytes reduced mod p
    // (~192 bits of challenge entropy; |F_{p^3}| = p^3 ~ 2^192).
    std::array<unsigned char, 24> b{};
    for (int i = 0; i < 24; ++i) b[static_cast<size_t>(i)] = static_cast<unsigned char>(i + 1);
    const gf::Fp3 ch = gf::FromChallengeBytes3(b.data());

    uint64_t w0 = 0, w1 = 0, w2 = 0;
    for (int i = 0; i < 8; ++i) {
        w0 |= static_cast<uint64_t>(b[static_cast<size_t>(i)]) << (8 * i);
        w1 |= static_cast<uint64_t>(b[static_cast<size_t>(8 + i)]) << (8 * i);
        w2 |= static_cast<uint64_t>(b[static_cast<size_t>(16 + i)]) << (8 * i);
    }
    BOOST_CHECK_EQUAL(gf::Canonical(ch.c0), w0 % gf::kP);
    BOOST_CHECK_EQUAL(gf::Canonical(ch.c1), w1 % gf::kP);
    BOOST_CHECK_EQUAL(gf::Canonical(ch.c2), w2 % gf::kP);

    // All-0xFF bytes exercise the mod-p reduction (2^64 - 1 >= p).
    std::array<unsigned char, 24> ff{};
    ff.fill(0xFF);
    const gf::Fp3 chf = gf::FromChallengeBytes3(ff.data());
    const uint64_t expect = 0xFFFFFFFFFFFFFFFFULL % gf::kP; // = 2^32 - 2
    BOOST_CHECK_EQUAL(gf::Canonical(chf.c0), expect);
    BOOST_CHECK_EQUAL(gf::Canonical(chf.c1), expect);
    BOOST_CHECK_EQUAL(gf::Canonical(chf.c2), expect);

    const auto trip = gf::ToU64Triple(ch);
    BOOST_CHECK_EQUAL(trip[0], gf::Canonical(ch.c0));
    BOOST_CHECK_EQUAL(trip[1], gf::Canonical(ch.c1));
    BOOST_CHECK_EQUAL(trip[2], gf::Canonical(ch.c2));
}

BOOST_AUTO_TEST_SUITE_END()
