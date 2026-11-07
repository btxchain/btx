// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcontrib.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcontrib_tests, BasicTestingSetup)

static modelnet::SwarmNotContrib NotedNote()
{
    modelnet::SwarmNotContrib note;
    note.worker_id = "worker-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_worker_id_is_worker)
{
    modelnet::SwarmNotContrib note = NotedNote();
    note.worker_id.clear();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotContribResult result = modelnet::SwarmNoteNotContrib(note, err);
    BOOST_CHECK_EQUAL(result.code, "WORKER");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.count, 0);
    BOOST_CHECK_EQUAL(err, "WORKER");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unverified)
{
    modelnet::SwarmNotContrib note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotContribResult result = modelnet::SwarmNoteNotContrib(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNVERIFIED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.count, 0);
    BOOST_CHECK_EQUAL(err, "UNVERIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotContrib note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotContribResult result = modelnet::SwarmNoteNotContrib(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.count, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
