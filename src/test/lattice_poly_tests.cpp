// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/lattice/ntt.h>
#include <shielded/lattice/poly.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(lattice_poly_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ntt_inverse_is_identity)
{
    Poly256 p;
    for (size_t i = 0; i < POLY_N; ++i) p.coeffs[i] = static_cast<int32_t>(i % POLY_Q);
    Poly256 original = p;

    p.NTT();
    p.InverseNTT();
    const int32_t mont = 4193792; // Dilithium's Montgomery factor.
    for (size_t i = 0; i < POLY_N; ++i) {
        p.coeffs[i] = Freeze(p.coeffs[i]);
        const int32_t scaled = static_cast<int32_t>((static_cast<int64_t>(original.coeffs[i]) * mont) % POLY_Q);
        original.coeffs[i] = Freeze(scaled);
        BOOST_CHECK_EQUAL(p.coeffs[i], original.coeffs[i]);
    }
}

BOOST_AUTO_TEST_CASE(addition_commutativity)
{
    Poly256 a, b;
    for (size_t i = 0; i < POLY_N; ++i) {
        a.coeffs[i] = static_cast<int32_t>((i * 17) % POLY_Q);
        b.coeffs[i] = static_cast<int32_t>((i * 31) % POLY_Q);
    }

    const Poly256 ab = a + b;
    const Poly256 ba = b + a;
    BOOST_CHECK(ab == ba);
}

BOOST_AUTO_TEST_CASE(zero_is_additive_identity)
{
    Poly256 a;
    for (size_t i = 0; i < POLY_N; ++i) a.coeffs[i] = static_cast<int32_t>((i * 7) % POLY_Q);
    Poly256 zero{};

    const Poly256 r = a + zero;
    BOOST_CHECK(r == a);
}

BOOST_AUTO_TEST_CASE(reduce_keeps_in_expected_range)
{
    Poly256 p;
    for (size_t i = 0; i < POLY_N; ++i) p.coeffs[i] = POLY_Q + static_cast<int32_t>(i);

    p.Reduce();
    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK(p.coeffs[i] >= -(POLY_Q / 2));
        BOOST_CHECK(p.coeffs[i] <= (POLY_Q / 2));
    }
}

BOOST_AUTO_TEST_CASE(pointwise_mul_in_ntt_domain)
{
    Poly256 a, b;
    for (size_t i = 0; i < POLY_N; ++i) {
        a.coeffs[i] = static_cast<int32_t>((i + 1) % POLY_Q);
        b.coeffs[i] = static_cast<int32_t>((i * 2 + 3) % POLY_Q);
    }

    a.NTT();
    b.NTT();
    const Poly256 c = Poly256::PointwiseMul(a, b);

    bool any_nonzero{false};
    for (const int32_t coeff : c.coeffs) {
        if (coeff != 0) {
            any_nonzero = true;
            break;
        }
    }
    BOOST_CHECK(any_nonzero);
}

BOOST_AUTO_TEST_CASE(inf_norm_computation)
{
    Poly256 p{};
    p.coeffs[0] = 100;
    p.coeffs[1] = -200;
    p.coeffs[2] = 50;
    BOOST_CHECK_EQUAL(p.InfNorm(), 200);
}

BOOST_AUTO_TEST_CASE(pack_unpack_roundtrip)
{
    Poly256 p{};
    for (size_t i = 0; i < POLY_N; ++i) {
        p.coeffs[i] = static_cast<int32_t>((i * 101) % POLY_Q);
    }

    const auto packed = p.Pack();
    const Poly256 unpacked = Poly256::Unpack(packed);
    BOOST_CHECK(unpacked == p);
}

BOOST_AUTO_TEST_SUITE_END()
