// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfinetune.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfinetune_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_id)
{
    modelnet::SwarmNotFineTune note;
    note.checkpoint_saved = true;
    note.want_publish = true;
    std::string err = "STALE";
    const modelnet::SwarmNotFineTuneResult result = modelnet::SwarmNoteNotFineTune(note, err);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(missing_checkpoint)
{
    modelnet::SwarmNotFineTune note;
    note.job_id = "job-1";
    note.checkpoint_saved = false;
    note.want_publish = false;
    std::string err = "STALE";
    const modelnet::SwarmNotFineTuneResult result = modelnet::SwarmNoteNotFineTune(note, err);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(missing_checkpoint_even_if_want_publish)
{
    modelnet::SwarmNotFineTune note;
    note.job_id = "job-1";
    note.checkpoint_saved = false;
    note.want_publish = true;
    std::string err = "STALE";
    const modelnet::SwarmNotFineTuneResult result = modelnet::SwarmNoteNotFineTune(note, err);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(want_publish_held)
{
    modelnet::SwarmNotFineTune note;
    note.job_id = "job-1";
    note.checkpoint_saved = true;
    note.want_publish = true;
    std::string err = "STALE";
    const modelnet::SwarmNotFineTuneResult result = modelnet::SwarmNoteNotFineTune(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotFineTune note;
    note.job_id = "job-1";
    note.checkpoint_saved = true;
    note.want_publish = false;
    std::string err = "STALE";
    const modelnet::SwarmNotFineTuneResult result = modelnet::SwarmNoteNotFineTune(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
