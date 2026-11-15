// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocoordstay2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocoordstay2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_row_id_is_row)
{
    modelnet::SwarmNotNoCoordStay2 note;
    note.coordinator_gone = true;
    note.want_drop = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCoordStay2Result result = modelnet::SwarmNoteNotNoCoordStay2(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK_EQUAL(result.code, "ROW");
    BOOST_CHECK_EQUAL(err, "ROW");
}

BOOST_AUTO_TEST_CASE(coordinator_gone_is_stays_when_want_drop_is_false)
{
    modelnet::SwarmNotNoCoordStay2 note;
    note.row_id = "row-1";
    note.coordinator_gone = true;
    note.want_drop = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCoordStay2Result result = modelnet::SwarmNoteNotNoCoordStay2(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK_EQUAL(result.code, "STAYS");
    BOOST_CHECK_EQUAL(err, "STAYS");
}

BOOST_AUTO_TEST_CASE(want_drop_is_held)
{
    modelnet::SwarmNotNoCoordStay2 note;
    note.row_id = "row-1";
    note.coordinator_gone = false;
    note.want_drop = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCoordStay2Result result = modelnet::SwarmNoteNotNoCoordStay2(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCoordStay2 note;
    note.row_id = "row-1";
    note.coordinator_gone = false;
    note.want_drop = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCoordStay2Result result = modelnet::SwarmNoteNotNoCoordStay2(note, err);
    BOOST_CHECK(!result.dropped);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
