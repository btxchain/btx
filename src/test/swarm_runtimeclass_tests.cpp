// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_experience/kind.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_runtimeclass/swarm_runtimeclass.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_runtimeclass_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tick_trains_hashes_moves_and_stores)
{
    constexpr uint64_t kSteps = 1;
    const int64_t outcome_ppm = static_cast<int64_t>(kSteps) * 1000;

    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(kSteps, cycle_err));
    const std::string state_hash = cycle.state_hash();
    const std::string expected = HexStr(Hash(state_hash));

    modelnet::SwarmExperience experience;
    std::string experience_err;
    BOOST_REQUIRE(experience.Store("job", modelnet::kExperiencePublic, outcome_ppm, experience_err));
    const int expected_reward = experience.reward("job");

    modelnet::SwarmRuntimeClass runtime;
    std::string err = "prior";
    BOOST_REQUIRE(runtime.Tick("job", kSteps, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(runtime.trained_steps() == cycle.steps());
    BOOST_CHECK(runtime.trained_steps() == kSteps);
    BOOST_CHECK_EQUAL(runtime.digest(), expected);
    BOOST_CHECK(runtime.digest() != state_hash);
    BOOST_CHECK_EQUAL(runtime.page_bytes(), static_cast<int64_t>(state_hash.size()));
    BOOST_CHECK(runtime.reward_of("job") == expected_reward);
    BOOST_CHECK(runtime.reward_of("missing") == -1);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(steps_below_one_do_nothing)
{
    modelnet::SwarmRuntimeClass runtime;
    std::string err = "prior";
    BOOST_CHECK(!runtime.Tick("job", 0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(runtime.trained_steps() == 0);
    BOOST_CHECK(runtime.digest().empty());
    BOOST_CHECK(runtime.page_bytes() == 0);
    BOOST_CHECK(runtime.reward_of("job") == -1);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(empty_id_is_work)
{
    modelnet::SwarmRuntimeClass runtime;
    std::string err = "prior";
    BOOST_CHECK(!runtime.Tick("", 1, err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(runtime.trained_steps() == 0);
    BOOST_CHECK(runtime.digest().empty());
    BOOST_CHECK(runtime.page_bytes() == 0);
    BOOST_CHECK(runtime.reward_of("") == -1);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(replay_of_the_same_id_does_not_run_more_steps)
{
    modelnet::SwarmRuntimeClass runtime;
    std::string err;
    BOOST_REQUIRE(runtime.Tick("job", 1, err));
    const uint64_t steps = runtime.trained_steps();
    const std::string digest = runtime.digest();
    const int64_t pages = runtime.page_bytes();
    const int reward = runtime.reward_of("job");
    BOOST_REQUIRE(steps == 1);
    BOOST_REQUIRE(!digest.empty());
    BOOST_REQUIRE(pages > 0);

    BOOST_CHECK(!runtime.Tick("job", 4, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(runtime.trained_steps() == steps);
    BOOST_CHECK_EQUAL(runtime.digest(), digest);
    BOOST_CHECK(runtime.page_bytes() == pages);
    BOOST_CHECK(runtime.reward_of("job") == reward);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(another_id_runs_more_steps)
{
    modelnet::SwarmRuntimeClass runtime;
    std::string err;
    BOOST_REQUIRE(runtime.Tick("job", 1, err));
    const uint64_t first_steps = runtime.trained_steps();
    const int64_t first_pages = runtime.page_bytes();
    const int first_reward = runtime.reward_of("job");

    BOOST_REQUIRE(runtime.Tick("other", 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(runtime.trained_steps() == first_steps + 1);
    BOOST_CHECK(runtime.page_bytes() > first_pages);
    BOOST_CHECK(runtime.reward_of("job") == first_reward);
    BOOST_CHECK(runtime.reward_of("other") == first_reward);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(gpu_tick_is_engine_absent)
{
    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(1, cycle_err));
    const std::string independent = HexStr(Hash(cycle.state_hash()));
    BOOST_REQUIRE(!independent.empty());

    modelnet::SwarmRuntimeClass runtime;
    std::string err = "prior";
    BOOST_CHECK(!runtime.GpuTick("job", 1, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(runtime.trained_steps() == 0);
    BOOST_CHECK(runtime.digest().empty());
    BOOST_CHECK(runtime.digest() != independent);
    BOOST_CHECK(runtime.page_bytes() == 0);
    BOOST_CHECK(runtime.reward_of("job") == -1);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(gpu_tick_leaves_a_stored_tick_unchanged)
{
    modelnet::SwarmRuntimeClass runtime;
    std::string err;
    BOOST_REQUIRE(runtime.Tick("job", 1, err));
    const uint64_t steps = runtime.trained_steps();
    const std::string digest = runtime.digest();
    const int64_t pages = runtime.page_bytes();
    const int reward = runtime.reward_of("job");

    BOOST_CHECK(!runtime.GpuTick("job", 3, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(runtime.trained_steps() == steps);
    BOOST_CHECK_EQUAL(runtime.digest(), digest);
    BOOST_CHECK(runtime.page_bytes() == pages);
    BOOST_CHECK(runtime.reward_of("job") == reward);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(private_tick_is_private_data)
{
    modelnet::SwarmRuntimeClass runtime;
    std::string err = "prior";
    BOOST_CHECK(!runtime.PrivateTick("secret", 1, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(runtime.trained_steps() == 0);
    BOOST_CHECK(runtime.digest().empty());
    BOOST_CHECK(runtime.page_bytes() == 0);
    BOOST_CHECK(runtime.reward_of("secret") == -1);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(private_tick_after_a_public_tick_stores_nothing)
{
    modelnet::SwarmRuntimeClass runtime;
    std::string err;
    BOOST_REQUIRE(runtime.Tick("job", 1, err));
    const uint64_t steps = runtime.trained_steps();
    const std::string digest = runtime.digest();
    const int64_t pages = runtime.page_bytes();
    const int reward = runtime.reward_of("job");

    BOOST_CHECK(!runtime.PrivateTick("secret", 2, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(runtime.trained_steps() == steps);
    BOOST_CHECK_EQUAL(runtime.digest(), digest);
    BOOST_CHECK(runtime.page_bytes() == pages);
    BOOST_CHECK(runtime.reward_of("job") == reward);
    BOOST_CHECK(runtime.reward_of("secret") == -1);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_CASE(remote_move_keeps_the_memory_copy)
{
    constexpr uint64_t kSteps = 1;

    modelnet::SwarmIntCycle cycle;
    std::string cycle_err;
    BOOST_REQUIRE(cycle.Run(kSteps, cycle_err));
    const std::string state_hash = cycle.state_hash();

    modelnet::SwarmRuntimeClass runtime;
    std::string err;
    BOOST_REQUIRE(runtime.Tick("job", kSteps, err));
    const uint64_t steps = runtime.trained_steps();
    const std::string digest = runtime.digest();
    const int64_t pages = runtime.page_bytes();
    const int reward = runtime.reward_of("job");
    BOOST_REQUIRE(pages == static_cast<int64_t>(state_hash.size()));
    BOOST_REQUIRE(!digest.empty());

    BOOST_CHECK(!runtime.RemoteMove(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(runtime.page_bytes() == pages);
    BOOST_CHECK_EQUAL(runtime.digest(), digest);
    BOOST_CHECK(runtime.trained_steps() == steps);
    BOOST_CHECK(runtime.reward_of("job") == reward);

    BOOST_CHECK(!runtime.RemoteMove(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(runtime.page_bytes() == pages);
    BOOST_CHECK(!runtime.launched());
    BOOST_CHECK(!runtime.gpu());
    BOOST_CHECK(!runtime.private_stored());
}

BOOST_AUTO_TEST_SUITE_END()
