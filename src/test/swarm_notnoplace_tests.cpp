// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoplace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoplace_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPlace note;
    note.want_place = true;
    const modelnet::SwarmNotNoPlaceResult result = modelnet::SwarmNoteNotNoPlace(note, err);
    BOOST_CHECK(!result.placed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(want_place_is_not_placed)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPlace note;
    note.page_id = "page-1";
    note.want_place = true;
    const modelnet::SwarmNotNoPlaceResult result = modelnet::SwarmNoteNotNoPlace(note, err);
    BOOST_CHECK(!result.placed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_PLACED");
    BOOST_CHECK_EQUAL(err, "NOT_PLACED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPlace note;
    note.page_id = "page-1";
    note.want_place = false;
    const modelnet::SwarmNotNoPlaceResult result = modelnet::SwarmNoteNotNoPlace(note, err);
    BOOST_CHECK(!result.placed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
