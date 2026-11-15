// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcrash.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcrash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotCrash note;
    std::string err = "stale";
    const modelnet::SwarmNotCrashResult result = modelnet::SwarmNoteNotCrash(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.restarted);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_recover_not_shown)
{
    modelnet::SwarmNotCrash note;
    note.node_id = "n1";
    note.want_recover = true;
    std::string err = "stale";
    const modelnet::SwarmNotCrashResult result = modelnet::SwarmNoteNotCrash(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHOWN");
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.restarted);
    BOOST_CHECK_EQUAL(err, "NOT_SHOWN");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotCrash note;
    note.node_id = "n1";
    std::string err = "stale";
    const modelnet::SwarmNotCrashResult result = modelnet::SwarmNoteNotCrash(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK(!result.restarted);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
