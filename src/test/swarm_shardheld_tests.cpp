// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardheld.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_shardheld_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_is_job)
{
    modelnet::SwarmShardHeld job;
    job.want_shard = true;
    std::string err = "prior";
    const modelnet::SwarmShardHeldResult result = modelnet::SwarmNoteShardHeld(job, err);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_shard_is_held)
{
    modelnet::SwarmShardHeld job;
    job.job_id = "job-a";
    job.want_shard = true;
    std::string err = "prior";
    const modelnet::SwarmShardHeldResult result = modelnet::SwarmNoteShardHeld(job, err);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_shard_false_is_noted)
{
    modelnet::SwarmShardHeld job;
    job.job_id = "job-a";
    job.want_shard = false;
    std::string err = "prior";
    const modelnet::SwarmShardHeldResult result = modelnet::SwarmNoteShardHeld(job, err);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
