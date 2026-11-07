// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reportrec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_reportrec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmReportRec report;
    report.want_record = true;
    std::string err = "prior";
    const modelnet::SwarmReportRecResult result = modelnet::SwarmNoteReportRec(report, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(want_record_is_held)
{
    modelnet::SwarmReportRec report;
    report.report_id = "report-1";
    report.want_record = true;
    std::string err = "prior";
    const modelnet::SwarmReportRecResult result = modelnet::SwarmNoteReportRec(report, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_record_false_is_noted)
{
    modelnet::SwarmReportRec report;
    report.report_id = "report-1";
    report.want_record = false;
    std::string err = "prior";
    const modelnet::SwarmReportRecResult result = modelnet::SwarmNoteReportRec(report, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
