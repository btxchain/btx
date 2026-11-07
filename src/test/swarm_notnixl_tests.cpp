// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnixl.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnixl_tests, BasicTestingSetup)

static modelnet::SwarmNotNixl NotedNote()
{
    modelnet::SwarmNotNixl note;
    note.page_id = "page-1";
    note.nixl_present = true;
    note.want_transfer = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_nixl)
{
    modelnet::SwarmNotNixl note = NotedNote();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNixlResult result = modelnet::SwarmNoteNotNixl(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NIXL");
    BOOST_CHECK_EQUAL(err, "NIXL");
}

BOOST_AUTO_TEST_CASE(want_transfer_without_nixl_is_engine_absent)
{
    modelnet::SwarmNotNixl note = NotedNote();
    note.nixl_present = false;
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotNixlResult result = modelnet::SwarmNoteNotNixl(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_transfer_with_nixl_is_held)
{
    modelnet::SwarmNotNixl note = NotedNote();
    note.nixl_present = true;
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotNixlResult result = modelnet::SwarmNoteNotNixl(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(nixl_present_without_transfer_is_noted)
{
    modelnet::SwarmNotNixl note = NotedNote();
    note.nixl_present = true;
    note.want_transfer = false;
    std::string err = "prior";
    const modelnet::SwarmNotNixlResult result = modelnet::SwarmNoteNotNixl(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
