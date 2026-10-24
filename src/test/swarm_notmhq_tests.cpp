// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmhq.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmhq_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    std::string err = "prior";
    modelnet::SwarmNotMhq note;
    note.hop_count = 2;
    note.want_qualify = true;
    const modelnet::SwarmNotMhqResult result = modelnet::SwarmNoteNotMhq(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(hop_count_two_without_want_qualify_is_unqualified)
{
    std::string err = "prior";
    modelnet::SwarmNotMhq note;
    note.route_id = "route-1";
    note.hop_count = 2;
    note.want_qualify = false;
    const modelnet::SwarmNotMhqResult result = modelnet::SwarmNoteNotMhq(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(hop_count_one_want_qualify_is_unqualified)
{
    std::string err = "prior";
    modelnet::SwarmNotMhq note;
    note.route_id = "route-1";
    note.hop_count = 1;
    note.want_qualify = true;
    const modelnet::SwarmNotMhqResult result = modelnet::SwarmNoteNotMhq(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(hop_count_one_plain_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotMhq note;
    note.route_id = "route-1";
    note.hop_count = 1;
    note.want_qualify = false;
    const modelnet::SwarmNotMhqResult result = modelnet::SwarmNoteNotMhq(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
