// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorefundmat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorefundmat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefundMat note;
    note.mature = false;
    note.want_refund = true;
    const modelnet::SwarmNotNoRefundMatResult result = modelnet::SwarmNoteNotNoRefundMat(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(immature_is_not_mature)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefundMat note;
    note.channel_id = "channel-1";
    note.mature = false;
    note.want_refund = false;
    const modelnet::SwarmNotNoRefundMatResult result = modelnet::SwarmNoteNotNoRefundMat(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_MATURE");
    BOOST_CHECK_EQUAL(err, "NOT_MATURE");
}

BOOST_AUTO_TEST_CASE(want_refund_when_mature_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefundMat note;
    note.channel_id = "channel-1";
    note.mature = true;
    note.want_refund = true;
    const modelnet::SwarmNotNoRefundMatResult result = modelnet::SwarmNoteNotNoRefundMat(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_mature_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefundMat note;
    note.channel_id = "channel-1";
    note.mature = true;
    note.want_refund = false;
    const modelnet::SwarmNotNoRefundMatResult result = modelnet::SwarmNoteNotNoRefundMat(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
