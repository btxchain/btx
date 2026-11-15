// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotimeout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotimeout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id)
{
    modelnet::SwarmNotNoTimeout note;
    note.refund_open = true;
    note.claim_open = true;
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTimeoutResult result = modelnet::SwarmNoteNotNoTimeout(note, err);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(both_open_is_race)
{
    modelnet::SwarmNotNoTimeout note;
    note.channel_id = "channel-1";
    note.refund_open = true;
    note.claim_open = true;
    note.want_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTimeoutResult result = modelnet::SwarmNoteNotNoTimeout(note, err);
    BOOST_CHECK_EQUAL(result.code, "RACE");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "RACE");
}

BOOST_AUTO_TEST_CASE(want_refund_is_held)
{
    modelnet::SwarmNotNoTimeout note;
    note.channel_id = "channel-1";
    note.refund_open = true;
    note.claim_open = false;
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTimeoutResult result = modelnet::SwarmNoteNotNoTimeout(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoTimeout note;
    note.channel_id = "channel-1";
    note.refund_open = false;
    note.claim_open = false;
    note.want_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTimeoutResult result = modelnet::SwarmNoteNotNoTimeout(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
