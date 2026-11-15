// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoagree.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoagree_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoAgree note;
    note.report_id.clear();
    note.agreed = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgreeResult result = modelnet::SwarmNoteNotNoAgree(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(agreed)
{
    modelnet::SwarmNotNoAgree note;
    note.report_id = "report-1";
    note.agreed = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgreeResult result = modelnet::SwarmNoteNotNoAgree(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLEMENT");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLEMENT");
}

BOOST_AUTO_TEST_CASE(want_settle_without_agreement)
{
    modelnet::SwarmNotNoAgree note;
    note.report_id = "report-1";
    note.agreed = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgreeResult result = modelnet::SwarmNoteNotNoAgree(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_without_agreement)
{
    modelnet::SwarmNotNoAgree note;
    note.report_id = "report-1";
    note.agreed = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAgreeResult result = modelnet::SwarmNoteNotNoAgree(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
