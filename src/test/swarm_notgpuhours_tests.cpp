// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgpuhours.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notgpuhours_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_id)
{
    modelnet::SwarmNotGpuHours note;
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotGpuHoursResult out = modelnet::SwarmNoteNotGpuHours(note, err);
    BOOST_CHECK_EQUAL(out.code, "JOB");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.gpu_hours, 0);
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_publish_unmeasured)
{
    modelnet::SwarmNotGpuHours note;
    note.job_id = "job-hours";
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotGpuHoursResult out = modelnet::SwarmNoteNotGpuHours(note, err);
    BOOST_CHECK_EQUAL(out.code, "UNMEASURED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.gpu_hours, 0);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotGpuHours note;
    note.job_id = "job-hours";
    std::string err = "stale";
    const modelnet::SwarmNotGpuHoursResult out = modelnet::SwarmNoteNotGpuHours(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.gpu_hours, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
