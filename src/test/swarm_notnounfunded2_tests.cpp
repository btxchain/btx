// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnounfunded2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnounfunded2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoUnfunded2 NotedNote()
{
    modelnet::SwarmNotNoUnfunded2 note;
    note.pool_id = "pool-1";
    note.unfunded = false;
    note.want_advertise = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmNotNoUnfunded2 note = NotedNote();
    note.pool_id.clear();
    note.unfunded = true;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfunded2Result result = modelnet::SwarmNoteNotNoUnfunded2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(unfunded_is_not_advertised)
{
    modelnet::SwarmNotNoUnfunded2 note = NotedNote();
    note.unfunded = true;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfunded2Result result = modelnet::SwarmNoteNotNoUnfunded2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADVERTISED");
    BOOST_CHECK_EQUAL(err, "NOT_ADVERTISED");
}

BOOST_AUTO_TEST_CASE(want_advertise_is_held)
{
    modelnet::SwarmNotNoUnfunded2 note = NotedNote();
    note.unfunded = false;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfunded2Result result = modelnet::SwarmNoteNotNoUnfunded2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoUnfunded2 note = NotedNote();
    note.unfunded = false;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfunded2Result result = modelnet::SwarmNoteNotNoUnfunded2(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
