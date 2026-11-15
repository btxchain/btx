// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notplacement.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notplacement_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    std::string err = "prior";
    modelnet::SwarmNotPlacement note;
    note.want_place = true;
    const modelnet::SwarmNotPlacementResult result = modelnet::SwarmNoteNotPlacement(note, err);
    BOOST_CHECK(!result.placed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(want_place_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotPlacement note;
    note.page_id = "page-a";
    note.want_place = true;
    const modelnet::SwarmNotPlacementResult result = modelnet::SwarmNoteNotPlacement(note, err);
    BOOST_CHECK(!result.placed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(page_without_place_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotPlacement note;
    note.page_id = "page-a";
    note.want_place = false;
    const modelnet::SwarmNotPlacementResult result = modelnet::SwarmNoteNotPlacement(note, err);
    BOOST_CHECK(!result.placed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
