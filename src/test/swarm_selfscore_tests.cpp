// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_selfscore.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_selfscore_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmSelfScore report;
    report.report_id.clear();
    report.same_author = false;
    report.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmSelfScoreResult result = modelnet::SwarmNoteSelfScore(report, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(same_author_without_want_score_is_not_scored)
{
    modelnet::SwarmSelfScore report;
    report.report_id = "report-1";
    report.same_author = true;
    report.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmSelfScoreResult result = modelnet::SwarmNoteSelfScore(report, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "NOT_SCORED");
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
}

BOOST_AUTO_TEST_CASE(want_score_with_other_author_is_held)
{
    modelnet::SwarmSelfScore report;
    report.report_id = "report-1";
    report.same_author = false;
    report.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmSelfScoreResult result = modelnet::SwarmNoteSelfScore(report, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(other_author_without_want_score_is_noted)
{
    modelnet::SwarmSelfScore report;
    report.report_id = "report-1";
    report.same_author = false;
    report.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmSelfScoreResult result = modelnet::SwarmNoteSelfScore(report, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
