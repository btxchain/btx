// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_visiblehead.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_visiblehead_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_head_id_is_head)
{
    std::string err = "prior";
    modelnet::SwarmHeadVisibility note;
    note.head_id.clear();
    note.graduated = true;
    note.public_requested = true;
    const modelnet::SwarmHeadVisibilityResult result = modelnet::SwarmNoteHeadVisibility(note, err);
    BOOST_CHECK(!result.visible);
    BOOST_CHECK_EQUAL(result.code, "HEAD");
    BOOST_CHECK_EQUAL(err, "HEAD");
}

BOOST_AUTO_TEST_CASE(ungraduated_is_private_even_when_public_requested)
{
    std::string err = "prior";
    modelnet::SwarmHeadVisibility note;
    note.head_id = "head-a";
    note.graduated = false;
    note.public_requested = false;
    const modelnet::SwarmHeadVisibilityResult private_note = modelnet::SwarmNoteHeadVisibility(note, err);
    BOOST_CHECK(!private_note.visible);
    BOOST_CHECK_EQUAL(private_note.code, "PRIVATE");
    BOOST_CHECK_EQUAL(err, "PRIVATE");

    note.public_requested = true;
    const modelnet::SwarmHeadVisibilityResult still_private = modelnet::SwarmNoteHeadVisibility(note, err);
    BOOST_CHECK(!still_private.visible);
    BOOST_CHECK_EQUAL(still_private.code, "PRIVATE");
    BOOST_CHECK_EQUAL(err, "PRIVATE");
}

BOOST_AUTO_TEST_CASE(public_request_is_held_and_not_visible)
{
    std::string err = "prior";
    modelnet::SwarmHeadVisibility note;
    note.head_id = "head-a";
    note.graduated = true;
    note.public_requested = true;
    const modelnet::SwarmHeadVisibilityResult result = modelnet::SwarmNoteHeadVisibility(note, err);
    BOOST_CHECK(!result.visible);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted_is_not_visible)
{
    std::string err = "prior";
    modelnet::SwarmHeadVisibility note;
    note.head_id = "head-a";
    note.graduated = true;
    note.public_requested = false;
    const modelnet::SwarmHeadVisibilityResult result = modelnet::SwarmNoteHeadVisibility(note, err);
    BOOST_CHECK(!result.visible);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
