// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoshard2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoshard2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotNoShard2 note;
    note.want_shard = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoShard2Result result = modelnet::SwarmNoteNotNoShard2(note, err);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
    BOOST_CHECK(!result.ran);
    BOOST_CHECK_EQUAL(result.gpus, 0);
}

BOOST_AUTO_TEST_CASE(want_shard)
{
    modelnet::SwarmNotNoShard2 note;
    note.run_id = "run-a";
    note.want_shard = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoShard2Result result = modelnet::SwarmNoteNotNoShard2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!result.ran);
    BOOST_CHECK_EQUAL(result.gpus, 0);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoShard2 note;
    note.run_id = "run-a";
    note.want_shard = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoShard2Result result = modelnet::SwarmNoteNotNoShard2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.ran);
    BOOST_CHECK_EQUAL(result.gpus, 0);
}

BOOST_AUTO_TEST_SUITE_END()
