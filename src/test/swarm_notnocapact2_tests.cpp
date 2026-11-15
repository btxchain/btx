// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocapact2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocapact2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_capability_id_is_capability)
{
    modelnet::SwarmNotNoCapAct2 note;
    note.uncovered = false;
    note.want_act = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapAct2Result result = modelnet::SwarmNoteNotNoCapAct2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "CAPABILITY");
    BOOST_CHECK_EQUAL(err, "CAPABILITY");
}

BOOST_AUTO_TEST_CASE(uncovered_true_is_not_acted_when_want_act_is_false)
{
    modelnet::SwarmNotNoCapAct2 note;
    note.capability_id = "cap-1";
    note.uncovered = true;
    note.want_act = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapAct2Result result = modelnet::SwarmNoteNotNoCapAct2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ACTED");
    BOOST_CHECK_EQUAL(err, "NOT_ACTED");
}

BOOST_AUTO_TEST_CASE(want_act_is_held)
{
    modelnet::SwarmNotNoCapAct2 note;
    note.capability_id = "cap-1";
    note.uncovered = false;
    note.want_act = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapAct2Result result = modelnet::SwarmNoteNotNoCapAct2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCapAct2 note;
    note.capability_id = "cap-1";
    note.uncovered = false;
    note.want_act = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapAct2Result result = modelnet::SwarmNoteNotNoCapAct2(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
