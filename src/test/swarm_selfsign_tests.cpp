// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_selfsign.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_selfsign_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmSelfSign report;
    report.report_id.clear();
    report.same_author = false;
    report.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSelfSignResult result = modelnet::SwarmNoteSelfSign(report, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(same_author_without_want_sign_is_not_signed)
{
    modelnet::SwarmSelfSign report;
    report.report_id = "report-1";
    report.same_author = true;
    report.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSelfSignResult result = modelnet::SwarmNoteSelfSign(report, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK(report.same_author);
    BOOST_CHECK(!report.want_sign);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign_with_other_author_is_held)
{
    modelnet::SwarmSelfSign report;
    report.report_id = "report-1";
    report.same_author = false;
    report.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmSelfSignResult result = modelnet::SwarmNoteSelfSign(report, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK(report.want_sign);
    BOOST_CHECK(!report.same_author);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(other_author_without_want_sign_is_noted)
{
    modelnet::SwarmSelfSign report;
    report.report_id = "report-1";
    report.same_author = false;
    report.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmSelfSignResult result = modelnet::SwarmNoteSelfSign(report, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK(!report.same_author);
    BOOST_CHECK(!report.want_sign);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
