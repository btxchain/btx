// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohfcard2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohfcard2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_card_id)
{
    modelnet::SwarmNotNoHfCard2 note;
    note.want_trust = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHfCard2Result result = modelnet::SwarmNoteNotNoHfCard2(note, err);
    BOOST_CHECK_EQUAL(result.code, "CARD");
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(err, "CARD");
}

BOOST_AUTO_TEST_CASE(want_trust)
{
    modelnet::SwarmNotNoHfCard2 note;
    note.card_id = "card-1";
    note.want_trust = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHfCard2Result result = modelnet::SwarmNoteNotNoHfCard2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoHfCard2 note;
    note.card_id = "card-1";
    note.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHfCard2Result result = modelnet::SwarmNoteNotNoHfCard2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
