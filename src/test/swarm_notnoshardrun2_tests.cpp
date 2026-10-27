// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoshardrun2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoshardrun2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoShardRun2 NotedNote()
{
    modelnet::SwarmNotNoShardRun2 note;
    note.run_id = "run-1";
    note.want_shard = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoShardRun2 note = NotedNote();
    note.run_id.clear();
    note.want_shard = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoShardRun2Result result = modelnet::SwarmNoteNotNoShardRun2(note, err);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_shard_is_held)
{
    modelnet::SwarmNotNoShardRun2 note = NotedNote();
    note.want_shard = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoShardRun2Result result = modelnet::SwarmNoteNotNoShardRun2(note, err);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoShardRun2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoShardRun2Result result = modelnet::SwarmNoteNotNoShardRun2(note, err);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
