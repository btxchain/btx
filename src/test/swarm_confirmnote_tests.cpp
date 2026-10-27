// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_confirmnote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_confirmnote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_is_channel)
{
    modelnet::SwarmConfirmNote note{"", 6, false};
    std::string err;
    const modelnet::SwarmConfirmNoteResult result = modelnet::SwarmNoteConfirmLocal(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK_EQUAL(result.confirmations, 0);
}

BOOST_AUTO_TEST_CASE(negative_confirmations_is_range)
{
    modelnet::SwarmConfirmNote note{"ch1", -1, false};
    std::string err;
    const modelnet::SwarmConfirmNoteResult result = modelnet::SwarmNoteConfirmLocal(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(result.confirmations, 0);
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_held)
{
    modelnet::SwarmConfirmNote note{"ch1", 6, true};
    std::string err;
    const modelnet::SwarmConfirmNoteResult result = modelnet::SwarmNoteConfirmLocal(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.confirmations, 6);
}

BOOST_AUTO_TEST_CASE(local_confirm_is_noted)
{
    modelnet::SwarmConfirmNote note{"ch1", 6, false};
    std::string err = "stale";
    const modelnet::SwarmConfirmNoteResult result = modelnet::SwarmNoteConfirmLocal(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.confirmations, 6);
}

BOOST_AUTO_TEST_SUITE_END()
