// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_intcycle_run_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(steps_below_one_do_not_call_the_trainer)
{
    modelnet::SwarmIntCycle cycle;
    std::string err = "prior";
    BOOST_CHECK(!cycle.Run(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(cycle.steps() == 0);
    BOOST_CHECK(cycle.state_hash().empty());
    BOOST_CHECK(cycle.State().step == 0);
}

BOOST_AUTO_TEST_CASE(one_step_matches_a_separate_integer_trainer)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    modelnet::SwarmIntCycle cycle;
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Run(1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cycle.steps() == 1);

    modelnet::IntegerTrainer trainer;
    std::string trainer_err;
    BOOST_REQUIRE(trainer.Run(1, trainer_err));
    BOOST_CHECK_EQUAL(cycle.state_hash(), modelnet::IntegerStateHash(trainer.State()));
    BOOST_CHECK_EQUAL(cycle.state_hash(), trainer.State().state_hash);
    BOOST_CHECK(cycle.steps() == trainer.State().step);
    BOOST_CHECK(cycle.State().weight == trainer.State().weight);
    BOOST_CHECK(cycle.State().bias == trainer.State().bias);
    BOOST_CHECK(cycle.State().cursor == trainer.State().cursor);

    BOOST_CHECK(!cycle.gpu());
    BOOST_CHECK(!cycle.distributed());
    BOOST_CHECK(!cycle.launched());
    BOOST_CHECK(!cycle.broadcast());
    BOOST_CHECK_EQUAL(cycle.automatic_spend(), "0");
    BOOST_CHECK(cycle.atoms_moved() == 0);
    BOOST_CHECK(cycle.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(a_refused_run_leaves_the_stored_hash)
{
    modelnet::SwarmIntCycle cycle;
    std::string err;
    BOOST_REQUIRE(cycle.Run(1, err));
    const std::string hash = cycle.state_hash();
    BOOST_CHECK(!hash.empty());

    BOOST_CHECK(!cycle.Run(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(cycle.steps() == 1);
    BOOST_CHECK_EQUAL(cycle.state_hash(), hash);
    BOOST_CHECK(cycle.State().step == 1);
}

BOOST_AUTO_TEST_SUITE_END()
