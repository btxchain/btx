// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdpheld.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fsdpheld_tests, BasicTestingSetup)

static modelnet::SwarmFsdpHeld NotedJob()
{
    modelnet::SwarmFsdpHeld job;
    job.job_id = "job-1";
    job.want_run = false;
    return job;
}

BOOST_AUTO_TEST_CASE(empty_job_is_job)
{
    modelnet::SwarmFsdpHeld job = NotedJob();
    job.job_id.clear();
    job.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmFsdpHeldResult result = modelnet::SwarmNoteFsdpHeld(job, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_run_is_held)
{
    modelnet::SwarmFsdpHeld job = NotedJob();
    job.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmFsdpHeldResult result = modelnet::SwarmNoteFsdpHeld(job, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_run_false_is_noted)
{
    modelnet::SwarmFsdpHeld job = NotedJob();
    job.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmFsdpHeldResult result = modelnet::SwarmNoteFsdpHeld(job, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.sharded);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
