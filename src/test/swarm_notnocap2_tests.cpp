// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocap2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocap2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cap_id_is_cap)
{
    modelnet::SwarmNotNoCap2 note;
    note.covered = false;
    note.want_act = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap2Result result = modelnet::SwarmNoteNotNoCap2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CAP");
    BOOST_CHECK_EQUAL(err, "CAP");
}

BOOST_AUTO_TEST_CASE(covered_false_is_not_acted_when_want_act_is_false)
{
    modelnet::SwarmNotNoCap2 note;
    note.cap_id = "cap-1";
    note.covered = false;
    note.want_act = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap2Result result = modelnet::SwarmNoteNotNoCap2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_ACTED");
    BOOST_CHECK_EQUAL(err, "NOT_ACTED");
}

BOOST_AUTO_TEST_CASE(want_act_is_held)
{
    modelnet::SwarmNotNoCap2 note;
    note.cap_id = "cap-1";
    note.covered = true;
    note.want_act = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap2Result result = modelnet::SwarmNoteNotNoCap2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCap2 note;
    note.cap_id = "cap-1";
    note.covered = true;
    note.want_act = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap2Result result = modelnet::SwarmNoteNotNoCap2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
