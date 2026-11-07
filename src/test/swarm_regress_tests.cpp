// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_regress.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_regress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_regression)
{
    modelnet::SwarmRegressionReport report;
    report.candidate_id.clear();
    report.suite_id = "suite-1";
    report.safety_regression = true;
    report.blocks_promotion = true;
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmAttachRegression(report, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!report.blocks_promotion);
    BOOST_CHECK(report.safety_regression);

    report.candidate_id = "cand-1";
    report.suite_id.clear();
    report.broad_regression = true;
    report.blocks_promotion = true;
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmAttachRegression(report, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!report.blocks_promotion);
}

BOOST_AUTO_TEST_CASE(safety_regression_blocks_promotion)
{
    modelnet::SwarmRegressionReport report;
    report.candidate_id = "cand-1";
    report.suite_id = "suite-1";
    report.safety_regression = true;
    report.broad_regression = false;
    report.blocks_promotion = false;
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmAttachRegression(report, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(report.blocks_promotion);
    BOOST_CHECK(report.safety_regression);
    BOOST_CHECK(!report.broad_regression);
}

BOOST_AUTO_TEST_CASE(broad_regression_blocks_promotion)
{
    modelnet::SwarmRegressionReport report;
    report.candidate_id = "cand-1";
    report.suite_id = "suite-1";
    report.safety_regression = false;
    report.broad_regression = true;
    report.blocks_promotion = false;
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmAttachRegression(report, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(report.blocks_promotion);
    BOOST_CHECK(!report.safety_regression);
    BOOST_CHECK(report.broad_regression);
}

BOOST_AUTO_TEST_CASE(neither_regression_allows_and_does_not_block)
{
    modelnet::SwarmRegressionReport report;
    report.candidate_id = "cand-1";
    report.suite_id = "suite-1";
    report.safety_regression = false;
    report.broad_regression = false;
    report.blocks_promotion = true;
    std::string err = "prior";
    BOOST_CHECK(modelnet::SwarmAttachRegression(report, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!report.blocks_promotion);
    BOOST_CHECK_EQUAL(report.candidate_id, "cand-1");
    BOOST_CHECK_EQUAL(report.suite_id, "suite-1");
}

BOOST_AUTO_TEST_SUITE_END()
