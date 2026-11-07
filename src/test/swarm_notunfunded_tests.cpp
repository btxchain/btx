// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notunfunded.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notunfunded_tests, BasicTestingSetup)

static modelnet::SwarmNotUnfunded NotedNote()
{
    modelnet::SwarmNotUnfunded note;
    note.pool_id = "pool-1";
    note.funded = true;
    note.want_advertise = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmNotUnfunded note = NotedNote();
    note.pool_id.clear();
    note.funded = false;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotUnfundedResult result = modelnet::SwarmNoteNotUnfunded(note, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(unfunded_is_not_holding)
{
    modelnet::SwarmNotUnfunded note = NotedNote();
    note.funded = false;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotUnfundedResult result = modelnet::SwarmNoteNotUnfunded(note, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOT_HOLDING");
    BOOST_CHECK_EQUAL(err, "NOT_HOLDING");
}

BOOST_AUTO_TEST_CASE(want_advertise_while_funded_is_not_holding)
{
    modelnet::SwarmNotUnfunded note = NotedNote();
    note.funded = true;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotUnfundedResult result = modelnet::SwarmNoteNotUnfunded(note, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOT_HOLDING");
    BOOST_CHECK_EQUAL(err, "NOT_HOLDING");
}

BOOST_AUTO_TEST_CASE(plain_funded_note_is_noted)
{
    modelnet::SwarmNotUnfunded note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotUnfundedResult result = modelnet::SwarmNoteNotUnfunded(note, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
