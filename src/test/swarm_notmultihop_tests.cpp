// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmultihop.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmultihop_tests, BasicTestingSetup)

static modelnet::SwarmNotMultiHop NotedNote()
{
    modelnet::SwarmNotMultiHop note;
    note.route_id = "route-1";
    note.hops = 1;
    note.want_qualify = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    modelnet::SwarmNotMultiHop note = NotedNote();
    note.route_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotMultiHopResult result = modelnet::SwarmNoteNotMultiHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(zero_hops_is_route)
{
    modelnet::SwarmNotMultiHop note = NotedNote();
    note.hops = 0;
    std::string err = "prior";
    const modelnet::SwarmNotMultiHopResult result = modelnet::SwarmNoteNotMultiHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(two_hops_want_qualify_is_unqualified)
{
    modelnet::SwarmNotMultiHop note = NotedNote();
    note.hops = 2;
    note.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmNotMultiHopResult result = modelnet::SwarmNoteNotMultiHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(one_hop_want_qualify_is_held)
{
    modelnet::SwarmNotMultiHop note = NotedNote();
    note.hops = 1;
    note.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmNotMultiHopResult result = modelnet::SwarmNoteNotMultiHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(one_hop_without_want_qualify_is_noted)
{
    modelnet::SwarmNotMultiHop note = NotedNote();
    note.hops = 1;
    note.want_qualify = false;
    std::string err = "prior";
    const modelnet::SwarmNotMultiHopResult result = modelnet::SwarmNoteNotMultiHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
