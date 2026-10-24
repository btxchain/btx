// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notroute.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notroute_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    std::string err = "prior";
    modelnet::SwarmNotRoute note;
    note.want_handle = true;
    const modelnet::SwarmNotRouteResult result = modelnet::SwarmNoteNotRoute(note, err);
    BOOST_CHECK(!result.handled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(want_handle_is_unqualified)
{
    std::string err = "prior";
    modelnet::SwarmNotRoute note;
    note.route_id = "route-a";
    note.want_handle = true;
    const modelnet::SwarmNotRouteResult result = modelnet::SwarmNoteNotRoute(note, err);
    BOOST_CHECK(!result.handled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(route_without_handle_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotRoute note;
    note.route_id = "route-a";
    note.want_handle = false;
    const modelnet::SwarmNotRouteResult result = modelnet::SwarmNoteNotRoute(note, err);
    BOOST_CHECK(!result.handled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
