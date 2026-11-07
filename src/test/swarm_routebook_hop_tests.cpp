// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/swarm_routebook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_routebook_hop_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_or_hop_is_route)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.AddHop("", "hop-a", 1, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!book.AddHop("route-a", "", 1, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!book.AddHop("", "", -1, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.hop_count(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.required_slack(""), static_cast<int64_t>(0));
    BOOST_CHECK(!book.qualified());
    int64_t expiry = 7;
    BOOST_CHECK(!book.cltv_expiry("route-a", "hop-a", expiry));
    BOOST_CHECK_EQUAL(expiry, static_cast<int64_t>(7));
}

BOOST_AUTO_TEST_CASE(negative_expiry_is_expiry)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.AddHop("route-a", "hop-a", -1, err));
    BOOST_CHECK_EQUAL(err, "EXPIRY");
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(0));
    BOOST_CHECK(!book.qualified());
    int64_t expiry = 7;
    BOOST_CHECK(!book.cltv_expiry("route-a", "hop-a", expiry));
    BOOST_CHECK_EQUAL(expiry, static_cast<int64_t>(7));
}

BOOST_AUTO_TEST_CASE(append_hop_does_not_qualify)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(book.AddHop("route-a", "hop-a", 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(book.required_slack("route-a"), static_cast<int64_t>(160));
    int64_t expiry = -1;
    BOOST_CHECK(book.cltv_expiry("route-a", "hop-a", expiry));
    BOOST_CHECK_EQUAL(expiry, static_cast<int64_t>(0));
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
    BOOST_CHECK(!book.signed_ok());
}

BOOST_AUTO_TEST_CASE(replay_keeps_first_expiry)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(book.AddHop("route-a", "hop-a", 40, err));
    BOOST_CHECK(!book.AddHop("route-a", "hop-a", 90, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(1));
    int64_t expiry = -1;
    BOOST_CHECK(book.cltv_expiry("route-a", "hop-a", expiry));
    BOOST_CHECK_EQUAL(expiry, static_cast<int64_t>(40));
    BOOST_CHECK(!book.AddHop("route-a", "hop-a", -5, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    int64_t again = -1;
    BOOST_CHECK(book.cltv_expiry("route-a", "hop-a", again));
    BOOST_CHECK_EQUAL(again, static_cast<int64_t>(40));
    BOOST_CHECK(!book.qualified());
}

BOOST_AUTO_TEST_CASE(distinct_hops_append_and_routes_stay_separate)
{
    modelnet::SwarmRouteBook book;
    std::string err = "prior";
    BOOST_CHECK(book.AddHop("route-a", "hop-a", 10, err));
    BOOST_CHECK(book.AddHop("route-a", "hop-b", 20, err));
    BOOST_CHECK(book.AddHop("route-b", "hop-a", 30, err));
    BOOST_CHECK_EQUAL(book.hop_count("route-a"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(book.hop_count("route-b"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(book.required_slack("route-a"), static_cast<int64_t>(320));
    int64_t expiry = -1;
    BOOST_CHECK(book.cltv_expiry("route-a", "hop-b", expiry));
    BOOST_CHECK_EQUAL(expiry, static_cast<int64_t>(20));
    BOOST_CHECK(book.cltv_expiry("route-b", "hop-a", expiry));
    BOOST_CHECK_EQUAL(expiry, static_cast<int64_t>(30));
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK_EQUAL(book.bound_delta("route-a"), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
