// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnounfund.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnounfund_tests, BasicTestingSetup)

static modelnet::SwarmNotNoUnfund NotedNote()
{
    modelnet::SwarmNotNoUnfund note;
    note.pool_id = "pool-1";
    note.funded = true;
    note.want_advertise = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmNotNoUnfund note = NotedNote();
    note.pool_id.clear();
    note.funded = false;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundResult result = modelnet::SwarmNoteNotNoUnfund(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(unfunded_is_unfunded)
{
    modelnet::SwarmNotNoUnfund note = NotedNote();
    note.funded = false;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundResult result = modelnet::SwarmNoteNotNoUnfund(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "UNFUNDED");
    BOOST_CHECK_EQUAL(err, "UNFUNDED");
}

BOOST_AUTO_TEST_CASE(want_advertise_while_funded_is_unfunded)
{
    modelnet::SwarmNotNoUnfund note = NotedNote();
    note.funded = true;
    note.want_advertise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundResult result = modelnet::SwarmNoteNotNoUnfund(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "UNFUNDED");
    BOOST_CHECK_EQUAL(err, "UNFUNDED");
}

BOOST_AUTO_TEST_CASE(funded_plain_is_noted)
{
    modelnet::SwarmNotNoUnfund note = NotedNote();
    note.funded = true;
    note.want_advertise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoUnfundResult result = modelnet::SwarmNoteNotNoUnfund(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
