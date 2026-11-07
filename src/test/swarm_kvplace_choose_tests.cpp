// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/swarm_kvplace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

namespace {

void ExpectStill(const modelnet::SwarmKvPlace& place)
{
    BOOST_CHECK_EQUAL(place.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!place.launched());
    BOOST_CHECK(!place.gpu());
    BOOST_CHECK(!place.measured_benchmark());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_kvplace_choose_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(continuation_reduces_only_idle)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    // Adjusted: recompute 10, idle 12-5=7, route 9, transfer 9.
    // Idle is the minimum. Route stays 9, so continuation did not reduce it.
    BOOST_CHECK(place.Choose(10, 12, 9, 9, 0, 0, 0, 5, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "idle");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(continuation_does_not_reduce_recompute_route_or_transfer)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    // Without the idle reduction, recompute at 4 would win over idle at 10.
    // Continuation of 3 brings idle to 7, still above recompute, still below route.
    BOOST_CHECK(place.Choose(4, 10, 8, 8, 0, 0, 0, 3, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(continuation_floors_idle_at_zero)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    // Idle base 5 minus 100 floors at 0. The other three stay 0.
    // A negative idle would have won the tie. The floor keeps a four-way tie.
    BOOST_CHECK(place.Choose(0, 5, 0, 0, 0, 0, 0, 100, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(missing_ppm_uses_integer_division)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    // 999/1000 is 0. Continuation floors idle, and every cost stays 0.
    BOOST_CHECK(place.Choose(0, 0, 0, 0, 999, 0, 0, 5, false, err));
    BOOST_CHECK_EQUAL(place.winner(), "recompute");

    // 1000/1000 is 1. Idle floors to 0 and the other three become 1.
    BOOST_CHECK(place.Choose(0, 0, 0, 0, 1000, 0, 0, 5, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "idle");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(memory_pressure_and_copies_raise_every_option)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    // Extra 4 on every option, then continuation 5 floors idle to 0.
    BOOST_CHECK(place.Choose(0, 0, 0, 0, 0, 4, 0, 5, false, err));
    BOOST_CHECK_EQUAL(place.winner(), "idle");

    BOOST_CHECK(place.Choose(0, 0, 0, 0, 0, 0, 4, 5, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "idle");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(negative_continuation_raises_idle_only)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    // Idle 4 minus -3 is 7. Recompute stays 6 and still wins.
    BOOST_CHECK(place.Choose(6, 4, 10, 10, 0, 0, 0, -3, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(transfer_without_an_engine_is_engine_absent_and_moves_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_CHECK(!place.Choose(5, 5, 5, 0, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(place.winner(), "transfer");
    BOOST_CHECK_EQUAL(place.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!place.launched());
    BOOST_CHECK(!place.gpu());
    BOOST_CHECK(!place.measured_benchmark());
}

BOOST_AUTO_TEST_CASE(transfer_with_an_engine_is_local_and_moves_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Choose(5, 5, 5, 0, 0, 0, 0, 0, true, err));
    BOOST_CHECK_EQUAL(err, "LOCAL");
    BOOST_CHECK_EQUAL(place.winner(), "transfer");
    BOOST_CHECK_EQUAL(place.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!place.launched());
    BOOST_CHECK(!place.gpu());
    BOOST_CHECK(!place.measured_benchmark());
}

BOOST_AUTO_TEST_CASE(a_later_non_transfer_clears_local)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Choose(5, 5, 5, 0, 0, 0, 0, 0, true, err));
    BOOST_CHECK_EQUAL(err, "LOCAL");
    BOOST_CHECK(place.Choose(1, 5, 5, 5, 0, 0, 0, 0, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(negative_inputs_are_pressure_and_store_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Choose(2, 3, 4, 5, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(place.winner(), "recompute");

    BOOST_CHECK(!place.Choose(-1, 3, 4, 5, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK_EQUAL(place.winner(), "recompute");

    BOOST_CHECK(!place.Choose(2, -1, 4, 5, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK(!place.Choose(2, 3, -1, 5, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK(!place.Choose(2, 3, 4, -1, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK(!place.Choose(2, 3, 4, 5, -1, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK(!place.Choose(2, 3, 4, 5, 0, -1, 0, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK(!place.Choose(2, 3, 4, 5, 0, 0, -1, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(pressure_on_the_first_choice_leaves_the_winner_empty)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Choose(1, 1, 1, 1, 0, 0, -5, 0, true, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK(place.winner().empty());
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(an_unrepresentable_sum_is_pressure_and_stores_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Choose(1, 1, 1, 1, 0, 0, 0, 0, false, err));
    const std::int64_t top = std::numeric_limits<std::int64_t>::max();
    BOOST_CHECK(!place.Choose(top, 1, 1, 1, 0, 0, 1, 0, false, err));
    BOOST_CHECK_EQUAL(err, "PRESSURE");
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_SUITE_END()
