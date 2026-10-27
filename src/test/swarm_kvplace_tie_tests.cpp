// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/swarm_kvplace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
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

BOOST_FIXTURE_TEST_SUITE(swarm_kvplace_tie_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(equal_costs_select_recompute_over_the_others)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    // Engine present must not turn a recompute tie into LOCAL.
    BOOST_CHECK(place.Choose(4, 4, 4, 4, 0, 0, 0, 0, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    BOOST_CHECK(place.winner() != "idle");
    BOOST_CHECK(place.winner() != "route");
    BOOST_CHECK(place.winner() != "transfer");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(equal_costs_with_a_shared_extra_still_select_recompute)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    // missing_ppm 2500 adds 2, memory_pressure 3, copies 4. Continuation is 0.
    // Every adjusted cost is 1+2+3+4. The tie stays with recompute.
    BOOST_CHECK(place.Choose(1, 1, 1, 1, 2500, 3, 4, 0, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(recompute_ties_idle_and_wins)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Choose(3, 3, 9, 9, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(recompute_ties_route_and_wins)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Choose(3, 8, 3, 9, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(recompute_ties_transfer_and_wins)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    // Transfer is tied with recompute and an engine is absent.
    // Recompute wins, so this is not ENGINE_ABSENT.
    BOOST_CHECK(place.Choose(3, 8, 8, 3, 0, 0, 0, 0, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "recompute");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(idle_wins_a_tie_with_route_when_recompute_is_higher)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Choose(9, 2, 2, 8, 0, 0, 0, 0, false, err));
    BOOST_CHECK_EQUAL(place.winner(), "idle");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(route_wins_a_tie_with_transfer_when_the_earlier_options_are_higher)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Choose(9, 8, 2, 2, 0, 0, 0, 0, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.winner(), "route");
    ExpectStill(place);
}

BOOST_AUTO_TEST_SUITE_END()
