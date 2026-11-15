// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_ckptsave_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_id_is_job)
{
    modelnet::SwarmCkptSave job;
    job.job_id.clear();
    job.want_save = false;
    std::string err = "prior";
    const modelnet::SwarmCkptSaveResult result = modelnet::SwarmNoteCkptSave(job, err);
    BOOST_CHECK(!result.saved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_save_true_is_held)
{
    modelnet::SwarmCkptSave job;
    job.job_id = "job-a";
    job.want_save = true;
    std::string err = "prior";
    const modelnet::SwarmCkptSaveResult result = modelnet::SwarmNoteCkptSave(job, err);
    BOOST_CHECK(!result.saved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_save_false_is_noted)
{
    modelnet::SwarmCkptSave job;
    job.job_id = "job-b";
    job.want_save = false;
    std::string err = "prior";
    const modelnet::SwarmCkptSaveResult result = modelnet::SwarmNoteCkptSave(job, err);
    BOOST_CHECK(!result.saved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
