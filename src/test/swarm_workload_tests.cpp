// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workload.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_workload_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_workload_id_is_work)
{
    modelnet::SwarmWorkload work;
    work.durable_atoms = 0;
    work.coordinator_gone = true;
    work.want_commit = true;
    std::string err = "prior";
    const modelnet::SwarmWorkloadResult result = modelnet::SwarmApplyWorkload(work, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.durable_atoms, int64_t{0});
    BOOST_CHECK(!result.volatile_kept);
    BOOST_CHECK_EQUAL(result.code, "WORK");
    BOOST_CHECK_EQUAL(err, "WORK");
}

BOOST_AUTO_TEST_CASE(coordinator_gone_is_durable_when_want_commit_is_false)
{
    modelnet::SwarmWorkload work;
    work.workload_id = "work-1";
    work.durable_atoms = 7000;
    work.volatile_task = "task";
    work.coordinator_gone = true;
    work.want_commit = false;
    std::string err = "prior";
    const modelnet::SwarmWorkloadResult result = modelnet::SwarmApplyWorkload(work, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.durable_atoms, int64_t{7000});
    BOOST_CHECK(!result.volatile_kept);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK_EQUAL(err, "DURABLE");
}

BOOST_AUTO_TEST_CASE(want_commit_is_held)
{
    modelnet::SwarmWorkload work;
    work.workload_id = "work-1";
    work.durable_atoms = 7000;
    work.volatile_task = "task";
    work.coordinator_gone = false;
    work.want_commit = true;
    std::string err = "prior";
    const modelnet::SwarmWorkloadResult result = modelnet::SwarmApplyWorkload(work, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.durable_atoms, work.durable_atoms);
    BOOST_CHECK(result.volatile_kept);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_workload_is_noted)
{
    modelnet::SwarmWorkload work;
    work.workload_id = "work-1";
    work.durable_atoms = 7000;
    work.volatile_task = "task";
    work.coordinator_gone = false;
    work.want_commit = false;
    std::string err = "prior";
    const modelnet::SwarmWorkloadResult result = modelnet::SwarmApplyWorkload(work, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.durable_atoms, work.durable_atoms);
    BOOST_CHECK(result.volatile_kept);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
