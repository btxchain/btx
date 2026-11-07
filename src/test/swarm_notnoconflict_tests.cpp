// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoconflict.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoconflict_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoConflict note;
    note.report_id.clear();
    note.conflicting = true;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoConflictResult result = modelnet::SwarmNoteNotNoConflict(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(conflicting)
{
    modelnet::SwarmNotNoConflict note;
    note.report_id = "report-1";
    note.conflicting = true;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoConflictResult result = modelnet::SwarmNoteNotNoConflict(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CONFLICT");
    BOOST_CHECK_EQUAL(err, "CONFLICT");
}

BOOST_AUTO_TEST_CASE(want_settle_without_conflict)
{
    modelnet::SwarmNotNoConflict note;
    note.report_id = "report-1";
    note.conflicting = false;
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoConflictResult result = modelnet::SwarmNoteNotNoConflict(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_without_conflict)
{
    modelnet::SwarmNotNoConflict note;
    note.report_id = "report-1";
    note.conflicting = false;
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoConflictResult result = modelnet::SwarmNoteNotNoConflict(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
