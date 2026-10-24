// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvnomove.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvnomove_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_kv)
{
    std::string err = "prior";
    modelnet::SwarmKvNoMove note;
    note.engine_present = true;
    note.want_transfer = true;
    const modelnet::SwarmKvNoMoveResult result = modelnet::SwarmNoteKvNoMove(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "KV");
    BOOST_CHECK_EQUAL(err, "KV");
}

BOOST_AUTO_TEST_CASE(want_transfer_without_engine_is_absent)
{
    std::string err = "prior";
    modelnet::SwarmKvNoMove note;
    note.page_id = "page-a";
    note.engine_present = false;
    note.want_transfer = true;
    const modelnet::SwarmKvNoMoveResult result = modelnet::SwarmNoteKvNoMove(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_transfer_with_engine_is_held)
{
    std::string err = "prior";
    modelnet::SwarmKvNoMove note;
    note.page_id = "page-a";
    note.engine_present = true;
    note.want_transfer = true;
    const modelnet::SwarmKvNoMoveResult result = modelnet::SwarmNoteKvNoMove(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(engine_present_without_transfer_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmKvNoMove note;
    note.page_id = "page-a";
    note.engine_present = true;
    note.want_transfer = false;
    const modelnet::SwarmKvNoMoveResult result = modelnet::SwarmNoteKvNoMove(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
