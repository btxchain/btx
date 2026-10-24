// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprefetch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notprefetch_tests, BasicTestingSetup)

static modelnet::SwarmNotPrefetch NotedNote()
{
    modelnet::SwarmNotPrefetch note;
    note.page_id = "page-1";
    note.want_prefetch = false;
    note.engine_present = true;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotPrefetch note = NotedNote();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotPrefetchResult result = modelnet::SwarmNoteNotPrefetch(note, err);
    BOOST_CHECK(!result.prefetched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(engine_absent_without_want_prefetch)
{
    modelnet::SwarmNotPrefetch note = NotedNote();
    note.engine_present = false;
    note.want_prefetch = false;
    std::string err = "prior";
    const modelnet::SwarmNotPrefetchResult result = modelnet::SwarmNoteNotPrefetch(note, err);
    BOOST_CHECK(!result.prefetched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_prefetch_with_engine_present_is_held)
{
    modelnet::SwarmNotPrefetch note = NotedNote();
    note.engine_present = true;
    note.want_prefetch = true;
    std::string err = "prior";
    const modelnet::SwarmNotPrefetchResult result = modelnet::SwarmNoteNotPrefetch(note, err);
    BOOST_CHECK(!result.prefetched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_with_engine_present_is_noted)
{
    modelnet::SwarmNotPrefetch note = NotedNote();
    note.engine_present = true;
    note.want_prefetch = false;
    std::string err = "prior";
    const modelnet::SwarmNotPrefetchResult result = modelnet::SwarmNoteNotPrefetch(note, err);
    BOOST_CHECK(!result.prefetched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
