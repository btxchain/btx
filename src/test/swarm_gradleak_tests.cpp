// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradleak.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_gradleak_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(raw_gradient_same_tenant_authorized_is_gradient_private)
{
    std::string err;
    const modelnet::SwarmGradientExport result = modelnet::SwarmExportGradient(true, true, true, false, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.contribution);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "GRADIENT_PRIVATE");
    BOOST_CHECK_EQUAL(err, "GRADIENT_PRIVATE");
}

BOOST_AUTO_TEST_CASE(training_time_claim_is_contribution)
{
    std::string err;
    const modelnet::SwarmGradientExport result = modelnet::SwarmExportGradient(false, true, true, true, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.contribution);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CONTRIBUTION");
    BOOST_CHECK_EQUAL(err, "CONTRIBUTION");
}

BOOST_AUTO_TEST_CASE(cross_tenant_non_raw_is_tenant)
{
    std::string err;
    const modelnet::SwarmGradientExport result = modelnet::SwarmExportGradient(false, false, true, false, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.contribution);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TENANT");
    BOOST_CHECK_EQUAL(err, "TENANT");
}

BOOST_AUTO_TEST_CASE(same_tenant_authorized_note_is_ok_and_is_not_a_payment)
{
    std::string err = "prior";
    const modelnet::SwarmGradientExport result = modelnet::SwarmExportGradient(false, true, true, false, err);
    BOOST_CHECK(result.allowed);
    BOOST_CHECK(!result.contribution);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "OK");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(raw_gradient_beats_a_training_claim)
{
    std::string err;
    const modelnet::SwarmGradientExport result = modelnet::SwarmExportGradient(true, true, true, true, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.contribution);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "GRADIENT_PRIVATE");
    BOOST_CHECK_EQUAL(err, "GRADIENT_PRIVATE");
}

BOOST_AUTO_TEST_SUITE_END()
