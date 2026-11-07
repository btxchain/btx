// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_intcycle_resume_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(step_zero_stays_not_resumable)
{
    modelnet::SwarmIntCycle cycle;
    std::string err = "prior";
    modelnet::IntegerState checkpoint;
    BOOST_CHECK(checkpoint.step == 0);
    BOOST_CHECK(!cycle.Resume(checkpoint, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_RESUMABLE");
    BOOST_CHECK(cycle.steps() == 0);
    BOOST_CHECK(cycle.state_hash().empty());
    BOOST_CHECK(cycle.State().step == 0);
}

BOOST_AUTO_TEST_CASE(resume_stores_the_checkpoint_hash_and_step)
{
    modelnet::IntegerTrainer source;
    std::string err;
    BOOST_REQUIRE(source.Run(4, err));
    const modelnet::IntegerState checkpoint = source.State();

    modelnet::SwarmIntCycle cycle;
    BOOST_REQUIRE(cycle.Resume(checkpoint, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cycle.steps() == 4);
    BOOST_CHECK_EQUAL(cycle.state_hash(), modelnet::IntegerStateHash(source.State()));
    BOOST_CHECK_EQUAL(cycle.state_hash(), modelnet::IntegerStateHash(cycle.State()));
    BOOST_CHECK(cycle.State().step == checkpoint.step);
    BOOST_CHECK(cycle.State().weight == checkpoint.weight);
    BOOST_CHECK(cycle.State().bias == checkpoint.bias);
    BOOST_CHECK(!cycle.gpu());
    BOOST_CHECK(!cycle.distributed());
    BOOST_CHECK_EQUAL(cycle.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(a_failed_resume_leaves_the_previous_hash)
{
    modelnet::SwarmIntCycle cycle;
    std::string err;
    BOOST_REQUIRE(cycle.Run(1, err));
    const std::string hash = cycle.state_hash();
    const uint64_t steps = cycle.steps();

    modelnet::IntegerState zero;
    BOOST_CHECK(!cycle.Resume(zero, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_RESUMABLE");
    BOOST_CHECK(cycle.steps() == steps);
    BOOST_CHECK_EQUAL(cycle.state_hash(), hash);
    BOOST_CHECK(cycle.State().step == 1);

    modelnet::IntegerTrainer source;
    BOOST_REQUIRE(source.Run(2, err));
    modelnet::IntegerState bad = source.State();
    bad.weight += 1;
    BOOST_CHECK(!cycle.Resume(bad, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");
    BOOST_CHECK(cycle.steps() == steps);
    BOOST_CHECK_EQUAL(cycle.state_hash(), hash);
    BOOST_CHECK(cycle.State().step == 1);
}

BOOST_AUTO_TEST_SUITE_END()
