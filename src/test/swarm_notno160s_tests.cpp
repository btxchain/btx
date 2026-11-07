// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno160s.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notno160s_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_clock_id_is_clock)
{
    std::string err = "prior";
    modelnet::SwarmNotNo160s note;
    note.blocks = 160;
    note.want_wallclock = true;
    const modelnet::SwarmNotNo160sResult result = modelnet::SwarmNoteNotNo160s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "CLOCK");
    BOOST_CHECK_EQUAL(err, "CLOCK");
}

BOOST_AUTO_TEST_CASE(blocks_not_160_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotNo160s note;
    note.clock_id = "clock-note";
    note.blocks = 159;
    note.want_wallclock = false;
    const modelnet::SwarmNotNo160sResult result = modelnet::SwarmNoteNotNo160s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_160_with_want_wallclock_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotNo160s note;
    note.clock_id = "clock-note";
    note.blocks = 160;
    note.want_wallclock = true;
    const modelnet::SwarmNotNo160sResult result = modelnet::SwarmNoteNotNo160s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_160_plain_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNo160s note;
    note.clock_id = "clock-note";
    note.blocks = 160;
    note.want_wallclock = false;
    const modelnet::SwarmNotNo160sResult result = modelnet::SwarmNoteNotNo160s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
