// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_assumedclose.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_assumedclose_tests, BasicTestingSetup)

static modelnet::SwarmAssumedClose NotedClose()
{
    modelnet::SwarmAssumedClose note;
    note.channel_id = "ch";
    note.assumed_bytes = 8000;
    note.want_measure = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_size)
{
    modelnet::SwarmAssumedClose note = NotedClose();
    note.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmAssumedCloseResult result = modelnet::SwarmNoteAssumedClose(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "SIZE");
    BOOST_CHECK_EQUAL(err, "SIZE");
}

BOOST_AUTO_TEST_CASE(negative_assumed_bytes_are_size)
{
    modelnet::SwarmAssumedClose note = NotedClose();
    note.assumed_bytes = -1;
    std::string err = "prior";
    const modelnet::SwarmAssumedCloseResult result = modelnet::SwarmNoteAssumedClose(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "SIZE");
    BOOST_CHECK_EQUAL(err, "SIZE");
}

BOOST_AUTO_TEST_CASE(want_measure_with_8000_is_measure_refused)
{
    modelnet::SwarmAssumedClose note = NotedClose();
    note.assumed_bytes = 8000;
    note.want_measure = true;
    std::string err = "prior";
    const modelnet::SwarmAssumedCloseResult result = modelnet::SwarmNoteAssumedClose(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "MEASURE_REFUSED");
    BOOST_CHECK_EQUAL(err, "MEASURE_REFUSED");
}

BOOST_AUTO_TEST_CASE(assumed_bytes_100_are_assumption)
{
    modelnet::SwarmAssumedClose note = NotedClose();
    note.assumed_bytes = 100;
    std::string err = "prior";
    const modelnet::SwarmAssumedCloseResult result = modelnet::SwarmNoteAssumedClose(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "ASSUMPTION");
    BOOST_CHECK_EQUAL(err, "ASSUMPTION");
}

BOOST_AUTO_TEST_CASE(eight_thousand_without_want_measure_is_noted)
{
    modelnet::SwarmAssumedClose note = NotedClose();
    std::string err = "prior";
    const modelnet::SwarmAssumedCloseResult result = modelnet::SwarmNoteAssumedClose(note, err);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
