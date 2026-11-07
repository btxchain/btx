// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohop.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohop_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHop note;
    note.hops = 2;
    note.want_qualify = true;
    const modelnet::SwarmNotNoHopResult result = modelnet::SwarmNoteNotNoHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(hops_greater_than_one_is_unqualified)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHop note;
    note.route_id = "route-1";
    note.hops = 2;
    note.want_qualify = false;
    const modelnet::SwarmNotNoHopResult result = modelnet::SwarmNoteNotNoHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(want_qualify_at_one_hop_is_unqualified)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHop note;
    note.route_id = "route-1";
    note.hops = 1;
    note.want_qualify = true;
    const modelnet::SwarmNotNoHopResult result = modelnet::SwarmNoteNotNoHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_one_hop_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHop note;
    note.route_id = "route-1";
    note.hops = 1;
    note.want_qualify = false;
    const modelnet::SwarmNotNoHopResult result = modelnet::SwarmNoteNotNoHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
