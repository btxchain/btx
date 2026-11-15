// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno90blk2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notno90blk2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_clock_id_is_clock)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90Blk2 note;
    note.want_guarantee = true;
    const modelnet::SwarmNotNo90Blk2Result result = modelnet::SwarmNoteNotNo90Blk2(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.code, "CLOCK");
    BOOST_CHECK_EQUAL(err, "CLOCK");
}

BOOST_AUTO_TEST_CASE(want_guarantee_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90Blk2 note;
    note.clock_id = "clock-note";
    note.want_guarantee = true;
    const modelnet::SwarmNotNo90Blk2Result result = modelnet::SwarmNoteNotNo90Blk2(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90Blk2 note;
    note.clock_id = "clock-note";
    note.want_guarantee = false;
    const modelnet::SwarmNotNo90Blk2Result result = modelnet::SwarmNoteNotNo90Blk2(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
