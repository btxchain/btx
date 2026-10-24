// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlmcache.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notlmcache_tests, BasicTestingSetup)

static modelnet::SwarmNotLmcache NotedNote()
{
    modelnet::SwarmNotLmcache note;
    note.page_id = "page-1";
    note.cuda_ops_present = true;
    note.want_transfer = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_cache)
{
    modelnet::SwarmNotLmcache note = NotedNote();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotLmcacheResult result = modelnet::SwarmNoteNotLmcache(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(want_transfer_without_cuda_ops_is_engine_absent)
{
    modelnet::SwarmNotLmcache note = NotedNote();
    note.cuda_ops_present = false;
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotLmcacheResult result = modelnet::SwarmNoteNotLmcache(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_transfer_with_cuda_ops_is_held)
{
    modelnet::SwarmNotLmcache note = NotedNote();
    note.cuda_ops_present = true;
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotLmcacheResult result = modelnet::SwarmNoteNotLmcache(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(cuda_ops_without_want_transfer_is_noted)
{
    modelnet::SwarmNotLmcache note = NotedNote();
    note.cuda_ops_present = true;
    note.want_transfer = false;
    std::string err = "prior";
    const modelnet::SwarmNotLmcacheResult result = modelnet::SwarmNoteNotLmcache(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
