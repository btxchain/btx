// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocallerate2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocallerate2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCallerRate2 NotedNote()
{
    modelnet::SwarmNotNoCallerRate2 note;
    note.engine_id = "engine-1";
    note.caller_rate = false;
    note.want_advertise = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_engine_id_is_engine)
{
    modelnet::SwarmNotNoCallerRate2 note = NotedNote();
    note.engine_id.clear();
    note.caller_rate = true;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCallerRate2Result result = modelnet::SwarmNoteNotNoCallerRate2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(caller_rate_is_not_advertised)
{
    modelnet::SwarmNotNoCallerRate2 note = NotedNote();
    note.caller_rate = true;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCallerRate2Result result = modelnet::SwarmNoteNotNoCallerRate2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADVERTISED");
    BOOST_CHECK_EQUAL(err, "NOT_ADVERTISED");
}

BOOST_AUTO_TEST_CASE(want_advertise_is_held)
{
    modelnet::SwarmNotNoCallerRate2 note = NotedNote();
    note.caller_rate = false;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCallerRate2Result result = modelnet::SwarmNoteNotNoCallerRate2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCallerRate2 note = NotedNote();
    note.caller_rate = false;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCallerRate2Result result = modelnet::SwarmNoteNotNoCallerRate2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
