// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notckpttime.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notckpttime_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_id_is_job)
{
    std::string err = "prior";
    modelnet::SwarmNotCkptTime note;
    note.checkpoint_saved = true;
    note.want_publish = true;
    const modelnet::SwarmNotCkptTimeResult result = modelnet::SwarmNoteNotCkptTime(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(missing_checkpoint_is_no_checkpoint_even_if_want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotCkptTime note;
    note.job_id = "job-ckpt";
    note.checkpoint_saved = false;
    note.want_publish = true;
    const modelnet::SwarmNotCkptTimeResult result = modelnet::SwarmNoteNotCkptTime(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotCkptTime note;
    note.job_id = "job-ckpt";
    note.checkpoint_saved = true;
    note.want_publish = true;
    const modelnet::SwarmNotCkptTimeResult result = modelnet::SwarmNoteNotCkptTime(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(saved_without_publish_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotCkptTime note;
    note.job_id = "job-ckpt";
    note.checkpoint_saved = true;
    note.want_publish = false;
    const modelnet::SwarmNotCkptTimeResult result = modelnet::SwarmNoteNotCkptTime(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
