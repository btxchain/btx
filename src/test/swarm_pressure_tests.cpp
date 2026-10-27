// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_pressure.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_pressure_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(continuation_makes_idle_uncached_cheaper)
{
    std::string err = "stale";
    const modelnet::SwarmPressureChoice loaded =
        modelnet::SwarmChoosePressured(100, 80, 70, 100, 2500, 3, 4, 0, false, err);
    BOOST_CHECK_EQUAL(loaded.choice, "ROUTE_TO_OWNER");
    BOOST_CHECK_EQUAL(loaded.cost, 70 + 2 + 3 + 4);
    BOOST_CHECK(loaded.code.empty());
    BOOST_CHECK(!loaded.bytes_moved);
    BOOST_CHECK(!loaded.measured_benchmark);
    BOOST_CHECK(err.empty());

    const modelnet::SwarmPressureChoice idle =
        modelnet::SwarmChoosePressured(100, 80, 70, 100, 2500, 3, 4, 40000, true, err);
    BOOST_CHECK_EQUAL(idle.choice, "IDLE_UNCACHED");
    BOOST_CHECK_EQUAL(idle.cost, 100 + 2 + 3 + 4 - 40);
    BOOST_CHECK(idle.code.empty());
    BOOST_CHECK(!idle.bytes_moved);
    BOOST_CHECK(!idle.measured_benchmark);
    BOOST_CHECK(err.empty());

    const modelnet::SwarmPressureChoice floored =
        modelnet::SwarmChoosePressured(10, 10, 10, 3, 0, 0, 0, 5000, false, err);
    BOOST_CHECK_EQUAL(floored.choice, "IDLE_UNCACHED");
    BOOST_CHECK_EQUAL(floored.cost, 0);
    BOOST_CHECK(!floored.bytes_moved);
    BOOST_CHECK(!floored.measured_benchmark);
}

BOOST_AUTO_TEST_CASE(transfer_without_an_engine_is_engine_absent)
{
    std::string err = "stale";
    const modelnet::SwarmPressureChoice choice =
        modelnet::SwarmChoosePressured(50, 10, 40, 40, 0, 0, 0, 0, false, err);
    BOOST_CHECK_EQUAL(choice.choice, "TRANSFER_KV");
    BOOST_CHECK_EQUAL(choice.cost, 10);
    BOOST_CHECK(!choice.bytes_moved);
    BOOST_CHECK(!choice.measured_benchmark);
    BOOST_CHECK_EQUAL(choice.code, "ENGINE_ABSENT");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(transfer_with_an_engine_is_local_and_moves_no_bytes)
{
    std::string err = "stale";
    const modelnet::SwarmPressureChoice choice =
        modelnet::SwarmChoosePressured(50, 10, 40, 40, 1999, 0, 0, 0, true, err);
    BOOST_CHECK_EQUAL(choice.choice, "TRANSFER_KV");
    BOOST_CHECK_EQUAL(choice.cost, 11);
    BOOST_CHECK(!choice.bytes_moved);
    BOOST_CHECK(!choice.measured_benchmark);
    BOOST_CHECK_EQUAL(choice.code, "LOCAL");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(ties_prefer_recompute_then_idle_then_route)
{
    std::string err = "stale";
    const modelnet::SwarmPressureChoice recompute =
        modelnet::SwarmChoosePressured(20, 20, 20, 20, 0, 1, 1, 0, true, err);
    BOOST_CHECK_EQUAL(recompute.choice, "RECOMPUTE_LOCAL");
    BOOST_CHECK_EQUAL(recompute.cost, 22);
    BOOST_CHECK(recompute.code.empty());
    BOOST_CHECK(!recompute.bytes_moved);

    const modelnet::SwarmPressureChoice idle =
        modelnet::SwarmChoosePressured(100, 40, 40, 40, 0, 0, 0, 0, false, err);
    BOOST_CHECK_EQUAL(idle.choice, "IDLE_UNCACHED");
    BOOST_CHECK(idle.code.empty());
    BOOST_CHECK(!idle.bytes_moved);

    const modelnet::SwarmPressureChoice route =
        modelnet::SwarmChoosePressured(100, 40, 40, 100, 0, 0, 0, 0, true, err);
    BOOST_CHECK_EQUAL(route.choice, "ROUTE_TO_OWNER");
    BOOST_CHECK(route.code.empty());
    BOOST_CHECK(!route.bytes_moved);
    BOOST_CHECK(!route.measured_benchmark);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(a_negative_input_is_pressure)
{
    std::string err = "stale";
    const modelnet::SwarmPressureChoice choice =
        modelnet::SwarmChoosePressured(-1, 10, 10, 10, 0, 0, 0, 0, true, err);
    BOOST_CHECK(choice.choice.empty());
    BOOST_CHECK(choice.code.empty());
    BOOST_CHECK_EQUAL(choice.cost, 0);
    BOOST_CHECK(!choice.bytes_moved);
    BOOST_CHECK(!choice.measured_benchmark);
    BOOST_CHECK_EQUAL(err, "PRESSURE");

    const modelnet::SwarmPressureChoice continuation =
        modelnet::SwarmChoosePressured(10, 10, 10, 10, 0, 0, 0, -1, false, err);
    BOOST_CHECK(continuation.choice.empty());
    BOOST_CHECK(!continuation.bytes_moved);
    BOOST_CHECK_EQUAL(err, "PRESSURE");
}

BOOST_AUTO_TEST_SUITE_END()
