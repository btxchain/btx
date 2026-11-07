// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnounfunded.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnounfunded_tests, BasicTestingSetup)

static modelnet::SwarmNotNoUnfunded NotedNote()
{
    modelnet::SwarmNotNoUnfunded note;
    note.pool_id = "pool-1";
    note.unfunded = false;
    note.want_advertise = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmNotNoUnfunded note = NotedNote();
    note.pool_id.clear();
    note.unfunded = true;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundedResult result = modelnet::SwarmNoteNotNoUnfunded(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(unfunded_is_not_held)
{
    modelnet::SwarmNotNoUnfunded note = NotedNote();
    note.unfunded = true;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundedResult result = modelnet::SwarmNoteNotNoUnfunded(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_HELD");
    BOOST_CHECK_EQUAL(err, "NOT_HELD");
}

BOOST_AUTO_TEST_CASE(want_advertise_is_held)
{
    modelnet::SwarmNotNoUnfunded note = NotedNote();
    note.unfunded = false;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundedResult result = modelnet::SwarmNoteNotNoUnfunded(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoUnfunded note = NotedNote();
    note.unfunded = false;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundedResult result = modelnet::SwarmNoteNotNoUnfunded(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
