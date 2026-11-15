// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_intcycle_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_steps_replay_match_a_second_trainer)
{
    modelnet::SwarmIntCycle cycle;
    std::string err;
    BOOST_REQUIRE(cycle.Run(2, err));
    BOOST_CHECK(cycle.steps() == 2);

    modelnet::IntegerTrainer second;
    BOOST_REQUIRE(second.Run(2, err));

    std::string replay_err = "prior";
    BOOST_CHECK(second.ReplayMatches(cycle.State(), replay_err));
    BOOST_CHECK(replay_err.empty());
    BOOST_CHECK_EQUAL(cycle.state_hash(), modelnet::IntegerStateHash(second.State()));
    BOOST_CHECK_EQUAL(cycle.State().state_hash, second.State().state_hash);
    BOOST_CHECK(cycle.State().step == second.State().step);
    BOOST_CHECK(cycle.State().weight == second.State().weight);
    BOOST_CHECK(cycle.State().bias == second.State().bias);
    BOOST_CHECK(cycle.State().momentum_w == second.State().momentum_w);
    BOOST_CHECK(cycle.State().momentum_b == second.State().momentum_b);
    BOOST_CHECK(cycle.State().cursor == second.State().cursor);
    BOOST_CHECK(!cycle.gpu());
    BOOST_CHECK(!cycle.distributed());
    BOOST_CHECK(!cycle.launched());
    BOOST_CHECK(!cycle.broadcast());
    BOOST_CHECK_EQUAL(cycle.automatic_spend(), "0");
    BOOST_CHECK(cycle.atoms_moved() == 0);
    BOOST_CHECK(cycle.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
