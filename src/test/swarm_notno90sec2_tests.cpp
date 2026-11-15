// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno90sec2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notno90sec2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_block_id_is_block)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90Sec2 note;
    note.wall_clock = true;
    note.want_guarantee = true;
    const modelnet::SwarmNotNo90Sec2Result result = modelnet::SwarmNoteNotNo90Sec2(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.code, "BLOCK");
    BOOST_CHECK_EQUAL(err, "BLOCK");
}

BOOST_AUTO_TEST_CASE(wall_clock_is_not_guaranteed)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90Sec2 note;
    note.block_id = "block-note";
    note.wall_clock = true;
    note.want_guarantee = false;
    const modelnet::SwarmNotNo90Sec2Result result = modelnet::SwarmNoteNotNo90Sec2(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEED");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEED");
}

BOOST_AUTO_TEST_CASE(want_guarantee_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90Sec2 note;
    note.block_id = "block-note";
    note.wall_clock = false;
    note.want_guarantee = true;
    const modelnet::SwarmNotNo90Sec2Result result = modelnet::SwarmNoteNotNo90Sec2(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90Sec2 note;
    note.block_id = "block-note";
    note.wall_clock = false;
    note.want_guarantee = false;
    const modelnet::SwarmNotNo90Sec2Result result = modelnet::SwarmNoteNotNo90Sec2(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
