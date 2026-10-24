// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohashlock2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohashlock2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHashlock2 note;
    note.hashlock = true;
    note.want_route = true;
    const modelnet::SwarmNotNoHashlock2Result result = modelnet::SwarmNoteNotNoHashlock2(note, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(hashlock_without_want_route_is_not_route)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHashlock2 note;
    note.route_id = "route-1";
    note.hashlock = true;
    note.want_route = false;
    const modelnet::SwarmNotNoHashlock2Result result = modelnet::SwarmNoteNotNoHashlock2(note, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROUTE");
    BOOST_CHECK_EQUAL(err, "NOT_ROUTE");
}

BOOST_AUTO_TEST_CASE(want_route_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHashlock2 note;
    note.route_id = "route-1";
    note.hashlock = false;
    note.want_route = true;
    const modelnet::SwarmNotNoHashlock2Result result = modelnet::SwarmNoteNotNoHashlock2(note, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHashlock2 note;
    note.route_id = "route-1";
    note.hashlock = false;
    note.want_route = false;
    const modelnet::SwarmNotNoHashlock2Result result = modelnet::SwarmNoteNotNoHashlock2(note, err);
    BOOST_CHECK(!result.routed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
