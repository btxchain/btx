// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/limits.h>
#include <modelnet/swarm_routebook/swarm_routebook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_routebook_slack_tests, BasicTestingSetup)

static bool AddHops(modelnet::SwarmRouteBook& book, const std::string& route, int64_t count, std::string& err)
{
    for (int64_t i = 0; i < count; ++i) {
        const std::string hop = "hop-" + std::to_string(i);
        if (!book.AddHop(route, hop, 100 + i, err)) {
            return false;
        }
    }
    return true;
}

BOOST_AUTO_TEST_CASE(zero_hops_require_0_and_stay_unqualified)
{
    modelnet::SwarmRouteBook book;
    BOOST_CHECK_EQUAL(modelnet::kSwarmRouteBookMargin, static_cast<int64_t>(160));
    BOOST_CHECK_EQUAL(book.hop_count("missing"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.required_slack("missing"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.required_slack("missing"), static_cast<int64_t>(0) * modelnet::kSwarmRouteBookMargin);
    std::string err = "prior";
    BOOST_CHECK(!book.Bind("missing", 0, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK_EQUAL(book.bound_delta("missing"), static_cast<int64_t>(0));
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_CASE(two_hops_require_320)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(AddHops(book, "route-2", 2, err));
    BOOST_CHECK_EQUAL(book.hop_count("route-2"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(book.required_slack("route-2"), static_cast<int64_t>(320));
    BOOST_CHECK_EQUAL(book.required_slack("route-2"), static_cast<int64_t>(2) * modelnet::kSwarmRouteBookMargin);
    BOOST_CHECK(!book.Bind("route-2", 319, err));
    BOOST_CHECK_EQUAL(err, "SLACK");
    BOOST_CHECK_EQUAL(book.bound_delta("route-2"), static_cast<int64_t>(0));
    BOOST_CHECK(book.Bind("route-2", 320, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.bound_delta("route-2"), static_cast<int64_t>(320));
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_CASE(three_hops_479_is_slack_and_480_binds_unqualified)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(AddHops(book, "route-3", 3, err));
    BOOST_CHECK_EQUAL(book.hop_count("route-3"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(book.required_slack("route-3"), static_cast<int64_t>(480));
    BOOST_CHECK_EQUAL(book.required_slack("route-3"), static_cast<int64_t>(3) * modelnet::kSwarmRouteBookMargin);
    BOOST_CHECK(!book.Bind("route-3", 479, err));
    BOOST_CHECK_EQUAL(err, "SLACK");
    BOOST_CHECK_EQUAL(book.bound_delta("route-3"), static_cast<int64_t>(0));
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(book.Bind("route-3", 480, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.bound_delta("route-3"), static_cast<int64_t>(480));
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK(!book.Bind("route-3", 479, err));
    BOOST_CHECK_EQUAL(err, "SLACK");
    BOOST_CHECK_EQUAL(book.bound_delta("route-3"), static_cast<int64_t>(480));
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_CASE(unknown_route_bind_is_route)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.Bind("route-missing", 480, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK_EQUAL(book.hop_count("route-missing"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.bound_delta("route-missing"), static_cast<int64_t>(0));
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_SUITE_END()
