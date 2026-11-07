// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disttrain/swarm_disttrain.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_disttrain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_replicas_match_an_independent_witness)
{
    constexpr uint64_t kSteps = 2;

    modelnet::SwarmIntCycle cycle_a;
    modelnet::SwarmIntCycle cycle_b;
    std::string cycle_err;
    BOOST_REQUIRE(cycle_a.Run(kSteps, cycle_err));
    BOOST_REQUIRE(cycle_b.Run(kSteps, cycle_err));
    const std::string hash_a = cycle_a.state_hash();
    const std::string hash_b = cycle_b.state_hash();
    const std::string expected = HexStr(Hash(hash_a + hash_b));
    BOOST_REQUIRE(!hash_a.empty());
    BOOST_REQUIRE(!hash_b.empty());
    BOOST_REQUIRE(!expected.empty());

    modelnet::SwarmDistTrain train;
    std::string err = "prior";
    BOOST_REQUIRE(train.Step(kSteps, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(train.witness(), expected);
    BOOST_CHECK(train.steps_done() == cycle_a.steps() + cycle_b.steps());
    BOOST_CHECK(train.steps_done() == kSteps + kSteps);
    BOOST_CHECK(!train.gpu());
    BOOST_CHECK(!train.distributed_gpu());
    BOOST_CHECK(!train.launched());
    BOOST_CHECK(!train.broadcast());
    BOOST_CHECK_EQUAL(train.automatic_spend(), "0");
    BOOST_CHECK(train.atoms_moved() == 0);
}

BOOST_AUTO_TEST_CASE(steps_below_one_call_neither_replica)
{
    modelnet::SwarmDistTrain train;
    std::string err = "prior";
    BOOST_CHECK(!train.Step(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(train.steps_done() == 0);
    BOOST_CHECK(train.witness().empty());
    BOOST_CHECK(!train.gpu());
    BOOST_CHECK(!train.distributed_gpu());
    BOOST_CHECK(!train.launched());
    BOOST_CHECK(!train.broadcast());
    BOOST_CHECK_EQUAL(train.automatic_spend(), "0");
    BOOST_CHECK(train.atoms_moved() == 0);
}

BOOST_AUTO_TEST_CASE(a_zero_step_after_success_leaves_the_witness)
{
    modelnet::SwarmDistTrain train;
    std::string err;
    BOOST_REQUIRE(train.Step(1, err));
    const uint64_t steps = train.steps_done();
    const std::string witness = train.witness();
    BOOST_REQUIRE(steps == 2);
    BOOST_REQUIRE(!witness.empty());

    BOOST_CHECK(!train.Step(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK(train.steps_done() == steps);
    BOOST_CHECK_EQUAL(train.witness(), witness);
    BOOST_CHECK(!train.gpu());
    BOOST_CHECK(!train.distributed_gpu());
    BOOST_CHECK(!train.launched());
}

BOOST_AUTO_TEST_CASE(gpu_fsdp_and_diloco_are_engine_absent)
{
    modelnet::SwarmDistTrain cold;
    std::string cold_err = "prior";
    BOOST_CHECK(!cold.GpuStep(1, cold_err));
    BOOST_CHECK_EQUAL(cold_err, "ENGINE_ABSENT");
    BOOST_CHECK(cold.steps_done() == 0);
    BOOST_CHECK(cold.witness().empty());
    BOOST_CHECK(!cold.gpu());
    BOOST_CHECK(!cold.distributed_gpu());
    BOOST_CHECK(!cold.launched());

    modelnet::SwarmDistTrain train;
    std::string err;
    BOOST_REQUIRE(train.Step(1, err));
    const uint64_t steps = train.steps_done();
    const std::string witness = train.witness();
    BOOST_REQUIRE(steps == 2);
    BOOST_REQUIRE(!witness.empty());

    BOOST_CHECK(!train.GpuStep(3, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(train.steps_done() == steps);
    BOOST_CHECK_EQUAL(train.witness(), witness);
    BOOST_CHECK(!train.gpu());
    BOOST_CHECK(!train.distributed_gpu());
    BOOST_CHECK(!train.launched());

    BOOST_CHECK(!train.FsdpStep(4, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(train.steps_done() == steps);
    BOOST_CHECK_EQUAL(train.witness(), witness);
    BOOST_CHECK(!train.gpu());
    BOOST_CHECK(!train.distributed_gpu());
    BOOST_CHECK(!train.launched());

    BOOST_CHECK(!train.DilocoStep(5, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(train.steps_done() == steps);
    BOOST_CHECK_EQUAL(train.witness(), witness);
    BOOST_CHECK(!train.gpu());
    BOOST_CHECK(!train.distributed_gpu());
    BOOST_CHECK(!train.launched());
    BOOST_CHECK(!train.broadcast());
    BOOST_CHECK_EQUAL(train.automatic_spend(), "0");
    BOOST_CHECK(train.atoms_moved() == 0);
}

BOOST_AUTO_TEST_CASE(export_grad_is_not_exported)
{
    modelnet::SwarmDistTrain train;
    std::string err;
    BOOST_REQUIRE(train.Step(1, err));
    const uint64_t steps = train.steps_done();
    const std::string witness = train.witness();

    BOOST_CHECK(!train.ExportGrad(err));
    BOOST_CHECK_EQUAL(err, "NOT_EXPORTED");
    BOOST_CHECK(train.steps_done() == steps);
    BOOST_CHECK_EQUAL(train.witness(), witness);
    BOOST_CHECK(train.atoms_moved() == 0);
    BOOST_CHECK(!train.gpu());
    BOOST_CHECK(!train.distributed_gpu());
    BOOST_CHECK(!train.launched());
}

BOOST_AUTO_TEST_SUITE_END()
