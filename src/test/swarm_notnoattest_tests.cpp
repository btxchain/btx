// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoattest.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoattest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmNotNoAttest note;
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAttestResult result = modelnet::SwarmNoteNotNoAttest(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmNotNoAttest note;
    note.report_id = "report-1";
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAttestResult result = modelnet::SwarmNoteNotNoAttest(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAttest note;
    note.report_id = "report-1";
    note.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAttestResult result = modelnet::SwarmNoteNotNoAttest(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
