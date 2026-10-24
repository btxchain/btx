// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_schedsim/dt_schedsim.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_schedsim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(four_microbatches_three_stages_count_slots)
{
    modelnet::DtSchedSim sim;
    std::string err;
    BOOST_CHECK_EQUAL(std::string(sim.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK(!sim.hardware_qualified());
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.dependencies(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(0));
    BOOST_CHECK(!sim.launched());
    BOOST_CHECK(!sim.gpu());
    BOOST_CHECK(!sim.broadcast());
    BOOST_CHECK_EQUAL(sim.automatic_spend(), "0");

    BOOST_CHECK(sim.Plan(4, 3, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(sim.microbatches(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(sim.stages(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(sim.dependencies(), static_cast<int64_t>(8));
    BOOST_CHECK(sim.dependency_to_next(0, 0));
    BOOST_CHECK(sim.dependency_to_next(3, 1));
    BOOST_CHECK(!sim.dependency_to_next(0, 2));
    BOOST_CHECK(!sim.slot_ready(0, 0));
    BOOST_CHECK_EQUAL(std::string(sim.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK(!sim.hardware_qualified());

    BOOST_CHECK(!sim.DualPipe(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(sim.dependencies(), static_cast<int64_t>(8));
    BOOST_CHECK(!sim.hardware_qualified());
    BOOST_CHECK(!sim.launched());
    BOOST_CHECK(!sim.gpu());
    BOOST_CHECK(!sim.broadcast());
    BOOST_CHECK_EQUAL(sim.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(shape_below_one_stores_nothing)
{
    modelnet::DtSchedSim sim;
    std::string err;
    BOOST_CHECK(!sim.Plan(0, 3, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.microbatches(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.stages(), static_cast<int64_t>(0));

    BOOST_CHECK(!sim.Plan(4, 0, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK(!sim.Plan(static_cast<int64_t>(-1), 3, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK(!sim.Plan(4, static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(0));
    BOOST_CHECK(!sim.Forward(0, 0, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(0));

    BOOST_CHECK(sim.Plan(4, 3, err));
    BOOST_CHECK(!sim.Plan(0, 3, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(sim.microbatches(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(sim.stages(), static_cast<int64_t>(3));
    BOOST_CHECK(!sim.hardware_qualified());
}

BOOST_AUTO_TEST_CASE(missing_previous_stage_is_dependency)
{
    modelnet::DtSchedSim sim;
    std::string err;
    BOOST_CHECK(sim.Plan(4, 3, err));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(0));

    BOOST_CHECK(!sim.Forward(0, 1, err));
    BOOST_CHECK_EQUAL(err, "DEPENDENCY");
    BOOST_CHECK(!sim.slot_ready(0, 1));
    BOOST_CHECK(sim.dependency_to_next(0, 0));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(2));

    BOOST_CHECK(sim.Forward(0, 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(sim.slot_ready(0, 0));
    BOOST_CHECK(sim.dependency_to_next(0, 0));
    BOOST_CHECK(!sim.slot_ready(0, 1));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(1));

    BOOST_CHECK(sim.Forward(0, 0, err));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(1));

    BOOST_CHECK(sim.Forward(0, 1, err));
    BOOST_CHECK(sim.slot_ready(0, 1));
    BOOST_CHECK(sim.dependency_to_next(0, 1));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(2));

    BOOST_CHECK(sim.Forward(0, 2, err));
    BOOST_CHECK(sim.slot_ready(0, 2));
    BOOST_CHECK(!sim.dependency_to_next(0, 2));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(3));

    BOOST_CHECK(!sim.Forward(1, 1, err));
    BOOST_CHECK_EQUAL(err, "DEPENDENCY");
    BOOST_CHECK(!sim.slot_ready(1, 1));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(3));

    BOOST_CHECK(!sim.Forward(4, 0, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK(!sim.Forward(static_cast<int64_t>(-1), 0, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(3));

    BOOST_CHECK(!sim.DualPipe(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(sim.bubbles_gpipe(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(sim.bubbles_1f1b(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(sim.ready_slots(), static_cast<int64_t>(3));
    BOOST_CHECK(!sim.hardware_qualified());
    BOOST_CHECK_EQUAL(std::string(sim.classification()), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
}

BOOST_AUTO_TEST_SUITE_END()
