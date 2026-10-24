// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_stepwork/swarm_stepwork.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_stepwork_gpu_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(gpu_record_leaves_the_experience_empty)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_CHECK(!work.GpuRecord("pub", 1, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!work.GpuRecord("", 0, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!work.GpuRecord("secret", 500, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!work.GpuRecord("wide", -1, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");

    BOOST_CHECK_EQUAL(work.size(), 0U);
    BOOST_CHECK_EQUAL(work.queued_count(), 0U);
    BOOST_CHECK(work.state_hash().empty());
    BOOST_CHECK_EQUAL(work.reward_of("pub"), -1);
    BOOST_CHECK(!work.offered("pub"));
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK(!work.private_stored());

    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(1, cycle_err));
    BOOST_CHECK(work.state_hash() != cycle.state_hash());
    BOOST_CHECK(!cycle.gpu());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_SUITE_END()
