// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdiscover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdiscover_tests, BasicTestingSetup)

static modelnet::SwarmNotDiscover NotedNote()
{
    modelnet::SwarmNotDiscover note;
    note.runtime_id = "runtime-1";
    note.want_discover = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_runtime_id_is_runtime)
{
    modelnet::SwarmNotDiscover note = NotedNote();
    note.runtime_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotDiscoverResult result = modelnet::SwarmNoteNotDiscover(note, err);
    BOOST_CHECK(!result.discovered);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "RUNTIME");
    BOOST_CHECK_EQUAL(err, "RUNTIME");
}

BOOST_AUTO_TEST_CASE(want_discover_is_not_found)
{
    modelnet::SwarmNotDiscover note = NotedNote();
    note.want_discover = true;
    std::string err = "prior";
    const modelnet::SwarmNotDiscoverResult result = modelnet::SwarmNoteNotDiscover(note, err);
    BOOST_CHECK(!result.discovered);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOT_FOUND");
    BOOST_CHECK_EQUAL(err, "NOT_FOUND");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDiscover note = NotedNote();
    note.want_discover = false;
    std::string err = "prior";
    const modelnet::SwarmNotDiscoverResult result = modelnet::SwarmNoteNotDiscover(note, err);
    BOOST_CHECK(!result.discovered);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
