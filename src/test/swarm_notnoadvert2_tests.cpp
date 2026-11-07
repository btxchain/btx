// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadvert2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoadvert2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoAdvert2 NotedNote()
{
    modelnet::SwarmNotNoAdvert2 note;
    note.sample_id = "sample-1";
    note.caller_rate = false;
    note.want_advertise = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_sample_id_is_sample)
{
    modelnet::SwarmNotNoAdvert2 note = NotedNote();
    note.sample_id.clear();
    note.caller_rate = true;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdvert2Result result = modelnet::SwarmNoteNotNoAdvert2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "SAMPLE");
    BOOST_CHECK_EQUAL(err, "SAMPLE");
}

BOOST_AUTO_TEST_CASE(caller_rate_is_not_advertised)
{
    modelnet::SwarmNotNoAdvert2 note = NotedNote();
    note.caller_rate = true;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdvert2Result result = modelnet::SwarmNoteNotNoAdvert2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADVERTISED");
    BOOST_CHECK_EQUAL(err, "NOT_ADVERTISED");
}

BOOST_AUTO_TEST_CASE(want_advertise_is_held)
{
    modelnet::SwarmNotNoAdvert2 note = NotedNote();
    note.caller_rate = false;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdvert2Result result = modelnet::SwarmNoteNotNoAdvert2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoAdvert2 note = NotedNote();
    note.caller_rate = false;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAdvert2Result result = modelnet::SwarmNoteNotNoAdvert2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
