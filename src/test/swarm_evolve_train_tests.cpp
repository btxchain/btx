// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_train_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_integer_step_is_stored_and_a_second_is_replay)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    modelnet::SwarmGeneration gen("subject-a", "baseline-parent", "coordinator-1");
    std::string err = "prior";
    BOOST_REQUIRE(gen.Train(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gen.Trained());
    BOOST_CHECK_EQUAL(gen.Step(), static_cast<uint64_t>(1));
    BOOST_CHECK(!gen.StateHash().empty());
    BOOST_CHECK_EQUAL(gen.StateHash(), gen.State().state_hash);
    BOOST_CHECK(!gen.GpuRan());

    modelnet::IntegerTrainer replay;
    BOOST_REQUIRE(replay.ReplayMatches(gen.State(), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(replay.State().step, static_cast<uint64_t>(0));

    modelnet::IntegerTrainer once;
    BOOST_REQUIRE(once.Step(err));
    BOOST_CHECK_EQUAL(gen.StateHash(), once.State().state_hash);
    BOOST_CHECK_EQUAL(gen.Step(), once.State().step);
    BOOST_REQUIRE(once.ReplayMatches(once.State(), err));

    const std::string hash = gen.StateHash();
    BOOST_CHECK(!gen.Train(err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gen.Step(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(gen.StateHash(), hash);
    BOOST_CHECK(!gen.GpuRan());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_SUITE_END()
