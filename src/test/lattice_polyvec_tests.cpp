// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/lattice/polymat.h>
#include <shielded/lattice/polyvec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(lattice_polyvec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(inner_product_self_nonzero)
{
    PolyVec v(MODULE_RANK);
    for (size_t i = 0; i < MODULE_RANK; ++i) {
        v[i].coeffs[0] = static_cast<int32_t>(i + 1);
    }

    const Poly256 ip = InnerProduct(v, v);
    BOOST_CHECK(ip.InfNorm() > 0);
}

BOOST_AUTO_TEST_CASE(matrix_vector_mul_dimensions)
{
    PolyMat mat(MODULE_RANK, PolyVec(MODULE_RANK));
    PolyVec vec(MODULE_RANK);

    for (size_t r = 0; r < MODULE_RANK; ++r) {
        for (size_t c = 0; c < MODULE_RANK; ++c) {
            mat[r][c].coeffs[0] = static_cast<int32_t>((r + 1) * (c + 2));
        }
        vec[r].coeffs[0] = static_cast<int32_t>(r + 3);
    }

    const PolyVec out = MatVecMul(mat, vec);
    BOOST_CHECK_EQUAL(out.size(), MODULE_RANK);
    for (const auto& p : out) {
        BOOST_CHECK(p.InfNorm() > 0);
    }
}

BOOST_AUTO_TEST_CASE(polyvec_add_sub_roundtrip)
{
    PolyVec a(MODULE_RANK), b(MODULE_RANK);

    for (size_t i = 0; i < MODULE_RANK; ++i) {
        a[i].coeffs[0] = static_cast<int32_t>(100 + i);
        b[i].coeffs[0] = static_cast<int32_t>(40 + i);
    }

    const PolyVec c = PolyVecAdd(a, b);
    const PolyVec d = PolyVecSub(c, b);

    BOOST_CHECK_EQUAL(d.size(), a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        BOOST_CHECK_EQUAL(d[i].coeffs[0], a[i].coeffs[0]);
    }
}

BOOST_AUTO_TEST_CASE(identity_matrix_mul)
{
    const PolyMat eye = PolyMatIdentity(MODULE_RANK);
    PolyVec vec(MODULE_RANK);

    for (size_t i = 0; i < MODULE_RANK; ++i) {
        vec[i].coeffs[0] = static_cast<int32_t>(i + 11);
    }

    const PolyVec out = MatVecMul(eye, vec);
    BOOST_CHECK_EQUAL(out.size(), vec.size());
    for (size_t i = 0; i < vec.size(); ++i) {
        BOOST_CHECK_EQUAL(out[i].coeffs[0], vec[i].coeffs[0]);
    }
}

BOOST_AUTO_TEST_CASE(polyvec_validity_checks_coefficient_bounds)
{
    PolyVec vec(MODULE_RANK);
    BOOST_CHECK(IsValidPolyVec(vec));

    vec[0].coeffs[5] = POLY_Q;
    BOOST_CHECK(!IsValidPolyVec(vec));

    vec[0].coeffs[5] = -POLY_Q;
    BOOST_CHECK(!IsValidPolyVec(vec));

    vec[0].coeffs[5] = POLY_Q - 1;
    BOOST_CHECK(IsValidPolyVec(vec));
}

BOOST_AUTO_TEST_SUITE_END()
