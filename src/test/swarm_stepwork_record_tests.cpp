// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_experience/kind.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_stepwork/swarm_stepwork.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_stepwork_record_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_public_step_matches_cycle_and_stored_reward)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_REQUIRE(work.Record("pub", 1, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK(!work.private_stored());
    BOOST_CHECK(!work.offered("pub"));
    BOOST_CHECK_EQUAL(work.size(), 1U);
    BOOST_CHECK_EQUAL(work.queued_count(), 1U);

    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(1, cycle_err));
    BOOST_CHECK_EQUAL(work.state_hash(), cycle.state_hash());

    const int64_t outcome_ppm = static_cast<int64_t>(1) * 1000;
    modelnet::SwarmExperience stored;
    std::string store_err;
    BOOST_REQUIRE(stored.Store("pub", modelnet::kExperiencePublic, outcome_ppm, store_err));
    BOOST_CHECK_EQUAL(work.reward_of("pub"), stored.reward("pub"));
    BOOST_CHECK_EQUAL(work.reward_of("missing"), -1);

    const std::string hash = work.state_hash();
    const int reward = work.reward_of("pub");
    BOOST_CHECK(!work.Record("pub", 2, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(work.state_hash(), hash);
    BOOST_CHECK_EQUAL(work.reward_of("pub"), reward);
    BOOST_CHECK_EQUAL(work.size(), 1U);
    BOOST_CHECK_EQUAL(work.queued_count(), 1U);
    BOOST_CHECK(!work.gpu());

    modelnet::SwarmIntCycle two;
    std::string two_err;
    BOOST_REQUIRE(two.Run(2, two_err));
    BOOST_CHECK(work.state_hash() != two.state_hash());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_CASE(empty_id_is_work_and_stores_nothing)
{
    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_CHECK(!work.Record("", 1, false, err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(!work.Record("", 1, true, err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(work.state_hash().empty());
    BOOST_CHECK_EQUAL(work.size(), 0U);
    BOOST_CHECK_EQUAL(work.queued_count(), 0U);
    BOOST_CHECK_EQUAL(work.reward_of(""), -1);
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK(!work.private_stored());
}

BOOST_AUTO_TEST_CASE(steps_below_one_do_not_call_the_trainer)
{
    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_CHECK(!work.Record("pub", 0, false, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(!work.Record("pub", -1, false, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(work.state_hash().empty());
    BOOST_CHECK_EQUAL(work.size(), 0U);
    BOOST_CHECK_EQUAL(work.queued_count(), 0U);
    BOOST_CHECK_EQUAL(work.reward_of("pub"), -1);
    BOOST_CHECK(!work.offered("pub"));
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK(!work.private_stored());
}

BOOST_AUTO_TEST_CASE(store_range_returns_the_store_error)
{
    modelnet::SwarmStepWork work;
    std::string err = "prior";
    BOOST_CHECK(!work.Record("wide", 1001, false, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(work.size(), 0U);
    BOOST_CHECK_EQUAL(work.queued_count(), 0U);
    BOOST_CHECK_EQUAL(work.reward_of("wide"), -1);
    BOOST_CHECK(!work.private_stored());
    BOOST_CHECK(!work.gpu());

    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(1001, cycle_err));
    BOOST_CHECK_EQUAL(work.state_hash(), cycle.state_hash());

    BOOST_REQUIRE(work.Record("pub", 1, false, err));
    BOOST_CHECK_EQUAL(work.size(), 1U);
    BOOST_CHECK(work.state_hash() != cycle.state_hash());
}

BOOST_AUTO_TEST_SUITE_END()
