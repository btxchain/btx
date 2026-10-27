// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_trainwire/swarm_trainwire.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_trainwire_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(step_two_matches_two_intcycle_witness)
{
    constexpr uint64_t kSteps = 2;

    modelnet::SwarmIntCycle cycle_a;
    modelnet::SwarmIntCycle cycle_b;
    std::string cycle_err;
    BOOST_REQUIRE(cycle_a.Run(kSteps, cycle_err));
    BOOST_REQUIRE(cycle_b.Run(kSteps, cycle_err));
    const std::string state_hash_a = cycle_a.state_hash();
    const std::string state_hash_b = cycle_b.state_hash();
    const std::string expected = HexStr(Hash(state_hash_a + state_hash_b));
    BOOST_REQUIRE(!state_hash_a.empty());
    BOOST_REQUIRE(!state_hash_b.empty());
    BOOST_REQUIRE(!expected.empty());

    modelnet::SwarmTrainWire wire;
    std::string err = "prior";
    BOOST_CHECK(!wire.trained());
    BOOST_REQUIRE(wire.Step(kSteps, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(wire.trained());
    BOOST_CHECK_EQUAL(wire.witness(), expected);
    BOOST_CHECK(wire.steps_done() == cycle_a.steps() + cycle_b.steps());
    BOOST_CHECK(wire.steps_done() == kSteps + kSteps);
    BOOST_CHECK(!wire.launched());
    BOOST_CHECK(!wire.gpu());
    BOOST_CHECK(!wire.distributed_gpu());
    BOOST_CHECK(!wire.broadcast());
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    BOOST_CHECK(wire.atoms_moved() == 0);

    const uint64_t steps = wire.steps_done();
    const std::string witness = wire.witness();
    BOOST_CHECK(!wire.GpuStep(3, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(wire.steps_done() == steps);
    BOOST_CHECK_EQUAL(wire.witness(), witness);
    BOOST_CHECK(wire.trained());
    BOOST_CHECK(!wire.gpu());
    BOOST_CHECK(!wire.launched());
    BOOST_CHECK(!wire.distributed_gpu());
    BOOST_CHECK(!wire.broadcast());
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    BOOST_CHECK(wire.atoms_moved() == 0);

    BOOST_CHECK(wire.Recover(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(wire.steps_done() == steps);
    BOOST_CHECK_EQUAL(wire.witness(), witness);
    BOOST_CHECK(wire.trained());
}

BOOST_AUTO_TEST_CASE(steps_below_one_call_nothing)
{
    modelnet::SwarmTrainWire wire;
    std::string err = "prior";
    BOOST_CHECK(!wire.Step(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(!wire.trained());
    BOOST_CHECK(wire.steps_done() == 0);
    BOOST_CHECK(wire.witness().empty());
    BOOST_CHECK(!wire.gpu());
    BOOST_CHECK(!wire.launched());
    BOOST_CHECK(!wire.distributed_gpu());
    BOOST_CHECK(!wire.broadcast());
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    BOOST_CHECK(wire.atoms_moved() == 0);

    BOOST_REQUIRE(wire.Step(2, err));
    const uint64_t steps = wire.steps_done();
    const std::string witness = wire.witness();
    BOOST_REQUIRE(wire.trained());
    BOOST_REQUIRE(!witness.empty());

    BOOST_CHECK(!wire.Step(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(wire.steps_done() == steps);
    BOOST_CHECK_EQUAL(wire.witness(), witness);
    BOOST_CHECK(wire.trained());
}

BOOST_AUTO_TEST_CASE(gpu_step_leaves_an_untrained_wire)
{
    modelnet::SwarmTrainWire wire;
    std::string err = "prior";
    BOOST_CHECK(!wire.GpuStep(2, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!wire.trained());
    BOOST_CHECK(wire.steps_done() == 0);
    BOOST_CHECK(wire.witness().empty());
    BOOST_CHECK(!wire.gpu());
    BOOST_CHECK(!wire.launched());
    BOOST_CHECK(!wire.distributed_gpu());
    BOOST_CHECK(!wire.broadcast());
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    BOOST_CHECK(wire.atoms_moved() == 0);

    BOOST_CHECK(!wire.Recover(err));
    BOOST_CHECK_EQUAL(err, "NOT_RESUMED");
    BOOST_CHECK(!wire.trained());
    BOOST_CHECK(wire.steps_done() == 0);
    BOOST_CHECK(wire.witness().empty());
}

BOOST_AUTO_TEST_CASE(recover_before_step_is_not_resumed)
{
    modelnet::SwarmTrainWire wire;
    std::string err = "prior";
    BOOST_CHECK(!wire.Recover(err));
    BOOST_CHECK_EQUAL(err, "NOT_RESUMED");
    BOOST_CHECK(!wire.trained());
    BOOST_CHECK(wire.steps_done() == 0);
    BOOST_CHECK(wire.witness().empty());
    BOOST_CHECK(!wire.gpu());
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    BOOST_CHECK(wire.atoms_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
