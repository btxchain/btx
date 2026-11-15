// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashroute.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_hashroute_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    modelnet::SwarmHashRoute route;
    route.route_id.clear();
    route.hashlock = false;
    route.want_route = false;
    std::string err = "stale";
    const modelnet::SwarmHashRouteResult result = modelnet::SwarmNoteHashRoute(route, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(hashlock_is_not_route)
{
    modelnet::SwarmHashRoute route;
    route.route_id = "record-1";
    route.hashlock = true;
    route.want_route = false;
    std::string err;
    const modelnet::SwarmHashRouteResult result = modelnet::SwarmNoteHashRoute(route, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROUTE");
    BOOST_CHECK_EQUAL(err, "NOT_ROUTE");
}

BOOST_AUTO_TEST_CASE(want_route_is_held)
{
    modelnet::SwarmHashRoute route;
    route.route_id = "record-2";
    route.hashlock = false;
    route.want_route = true;
    std::string err;
    const modelnet::SwarmHashRouteResult result = modelnet::SwarmNoteHashRoute(route, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_clears_err)
{
    modelnet::SwarmHashRoute route;
    route.route_id = "record-3";
    route.hashlock = false;
    route.want_route = false;
    std::string err = "stale";
    const modelnet::SwarmHashRouteResult result = modelnet::SwarmNoteHashRoute(route, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
