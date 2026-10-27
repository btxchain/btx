// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopermcoord.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopermcoord_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_coord_id_is_coord)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPermCoord note;
    note.gone = true;
    note.want_replace = true;
    const modelnet::SwarmNotNoPermCoordResult result = modelnet::SwarmNoteNotNoPermCoord(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(gone_is_permanent)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPermCoord note;
    note.coord_id = "coord-note";
    note.gone = true;
    note.want_replace = false;
    const modelnet::SwarmNotNoPermCoordResult result = modelnet::SwarmNoteNotNoPermCoord(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "PERMANENT");
    BOOST_CHECK_EQUAL(err, "PERMANENT");
}

BOOST_AUTO_TEST_CASE(want_replace_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPermCoord note;
    note.coord_id = "coord-note";
    note.gone = false;
    note.want_replace = true;
    const modelnet::SwarmNotNoPermCoordResult result = modelnet::SwarmNoteNotNoPermCoord(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPermCoord note;
    note.coord_id = "coord-note";
    note.gone = false;
    note.want_replace = false;
    const modelnet::SwarmNotNoPermCoordResult result = modelnet::SwarmNoteNotNoPermCoord(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
