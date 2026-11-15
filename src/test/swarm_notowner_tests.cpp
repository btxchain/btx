// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notowner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notowner_tests, BasicTestingSetup)

static modelnet::SwarmNotOwner NotedPage()
{
    modelnet::SwarmNotOwner note;
    note.page_id = "page-1";
    note.want_transfer = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotOwner note = NotedPage();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotOwnerResult result = modelnet::SwarmNoteNotOwner(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(want_transfer_is_not_shown)
{
    modelnet::SwarmNotOwner note = NotedPage();
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotOwnerResult result = modelnet::SwarmNoteNotOwner(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHOWN");
    BOOST_CHECK_EQUAL(err, "NOT_SHOWN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotOwner note = NotedPage();
    std::string err = "prior";
    const modelnet::SwarmNotOwnerResult result = modelnet::SwarmNoteNotOwner(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
