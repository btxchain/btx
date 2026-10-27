// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohashlock.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohashlock_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    modelnet::SwarmNotNoHashlock note;
    note.route_id.clear();
    note.hashlock_only = true;
    note.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHashlockResult result = modelnet::SwarmNoteNotNoHashlock(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(hashlock_only_is_unqualified)
{
    modelnet::SwarmNotNoHashlock note;
    note.route_id = "route-1";
    note.hashlock_only = true;
    note.want_qualify = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHashlockResult result = modelnet::SwarmNoteNotNoHashlock(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(want_qualify_is_unqualified)
{
    modelnet::SwarmNotNoHashlock note;
    note.route_id = "route-1";
    note.hashlock_only = false;
    note.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHashlockResult result = modelnet::SwarmNoteNotNoHashlock(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_route_is_noted)
{
    modelnet::SwarmNotNoHashlock note;
    note.route_id = "route-1";
    note.hashlock_only = false;
    note.want_qualify = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHashlockResult result = modelnet::SwarmNoteNotNoHashlock(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
