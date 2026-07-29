// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri_ext3_alg_order_audit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_fri_ext3_alg_order_audit_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    legacy_alpha_before_evals_has_explicit_cancellation_kernel)
{
    const std::vector<rc::Fp3> coefficients{
        gf::Fp3::FromFp(gf::FromU64(3)),
        gf::Fp3::FromFp(gf::FromU64(5)),
        gf::Fp3::FromFp(gf::FromU64(7)),
    };
    const std::vector<uint32_t> lengths{5, 8, 7};
    const rc::Fp3 z1{
        gf::FromU64(11),
        gf::FromU64(13),
        gf::FromU64(17)};
    const rc::Fp3 z2{
        gf::FromU64(19),
        gf::FromU64(23),
        gf::FromU64(29)};
    const std::vector<rc::Fp3> evals_z1{
        gf::Fp3::FromFp(gf::FromU64(31)),
        gf::Fp3::FromFp(gf::FromU64(37)),
        gf::Fp3::FromFp(gf::FromU64(41)),
    };
    const std::vector<rc::Fp3> evals_z2{
        gf::Fp3::FromFp(gf::FromU64(43)),
        gf::Fp3::FromFp(gf::FromU64(47)),
        gf::Fp3::FromFp(gf::FromU64(53)),
    };
    const auto audit =
        rc::AuditFri3AlgAdaptiveEvaluationOrder(
            coefficients, lengths, 8,
            z1, z2, evals_z1, evals_z2);
    BOOST_CHECK(audit.z1_claim_vector_changed);
    BOOST_CHECK(audit.z2_claim_vector_changed);
    BOOST_CHECK(audit.z1_batched_value_unchanged);
    BOOST_CHECK(audit.z2_batched_value_unchanged);
    BOOST_CHECK(
        gf::Eq(
            audit.honest_batched_z1,
            audit.forged_batched_z1));
    BOOST_CHECK(
        gf::Eq(
            audit.honest_batched_z2,
            audit.forged_batched_z2));
    BOOST_CHECK(
        audit.self_consistent_legacy_kernel_exhibited);
    BOOST_CHECK(
        !audit.legacy_order_individual_eval_binding);
    BOOST_CHECK(
        audit.
            post_claim_random_batching_blocks_adaptive_kernel);
    BOOST_CHECK_EQUAL(
        audit.conservative_post_claim_binding_bits,
        191U);
}

BOOST_AUTO_TEST_CASE(
    audit_fails_closed_without_two_nonzero_weight_coordinates)
{
    const std::vector<rc::Fp3> coefficients{
        rc::Fp3::One(),
        rc::Fp3::Zero(),
    };
    const std::vector<uint32_t> lengths{2, 2};
    const std::vector<rc::Fp3> evals{
        rc::Fp3::One(),
        rc::Fp3::One(),
    };
    const auto audit =
        rc::AuditFri3AlgAdaptiveEvaluationOrder(
            coefficients, lengths, 2,
            rc::Fp3::One(), rc::Fp3::One(),
            evals, evals);
    BOOST_CHECK(
        !audit.self_consistent_legacy_kernel_exhibited);
    BOOST_CHECK(
        !audit.legacy_order_individual_eval_binding);
    BOOST_CHECK_EQUAL(
        audit.conservative_post_claim_binding_bits,
        0U);
}

BOOST_AUTO_TEST_SUITE_END()
