// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsponsor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsponsor_tests, BasicTestingSetup)

static modelnet::SwarmNotSponsor NotedNote()
{
    modelnet::SwarmNotSponsor note;
    note.admin_id = "admin-1";
    note.want_move_key = false;
    note.want_move_height = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotSponsor note = NotedNote();
    note.admin_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotSponsorResult result = modelnet::SwarmNoteNotSponsor(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.height_changed);
    BOOST_CHECK_EQUAL(result.code, "ADMIN");
    BOOST_CHECK_EQUAL(err, "ADMIN");
}

BOOST_AUTO_TEST_CASE(want_move_key)
{
    modelnet::SwarmNotSponsor note = NotedNote();
    note.want_move_key = true;
    note.want_move_height = false;
    std::string err = "prior";
    const modelnet::SwarmNotSponsorResult result = modelnet::SwarmNoteNotSponsor(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.height_changed);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(want_move_height)
{
    modelnet::SwarmNotSponsor note = NotedNote();
    note.want_move_key = false;
    note.want_move_height = true;
    std::string err = "prior";
    const modelnet::SwarmNotSponsorResult result = modelnet::SwarmNoteNotSponsor(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.height_changed);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain)
{
    modelnet::SwarmNotSponsor note = NotedNote();
    note.want_move_key = false;
    note.want_move_height = false;
    std::string err = "prior";
    const modelnet::SwarmNotSponsorResult result = modelnet::SwarmNoteNotSponsor(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.height_changed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
