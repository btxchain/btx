// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notvram.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notvram_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_id)
{
    modelnet::SwarmNotVram note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotVramResult result = modelnet::SwarmNoteNotVram(note, err);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.vram_bytes, 0);
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    modelnet::SwarmNotVram note;
    note.job_id = "job-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotVramResult result = modelnet::SwarmNoteNotVram(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.vram_bytes, 0);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotVram note;
    note.job_id = "job-1";
    std::string err = "prior";
    const modelnet::SwarmNotVramResult result = modelnet::SwarmNoteNotVram(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.vram_bytes, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
