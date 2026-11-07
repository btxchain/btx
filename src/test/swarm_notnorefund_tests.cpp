// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorefund.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorefund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefund note;
    note.refund_signed = false;
    note.want_count_funding = true;
    const modelnet::SwarmNotNoRefundResult result = modelnet::SwarmNoteNotNoRefund(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(unsigned_refund_is_unsigned)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefund note;
    note.channel_id = "channel-1";
    note.refund_signed = false;
    note.want_count_funding = false;
    const modelnet::SwarmNotNoRefundResult result = modelnet::SwarmNoteNotNoRefund(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(want_count_funding_when_signed_is_unsigned)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefund note;
    note.channel_id = "channel-1";
    note.refund_signed = true;
    note.want_count_funding = true;
    const modelnet::SwarmNotNoRefundResult result = modelnet::SwarmNoteNotNoRefund(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(plain_signed_refund_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoRefund note;
    note.channel_id = "channel-1";
    note.refund_signed = true;
    note.want_count_funding = false;
    const modelnet::SwarmNotNoRefundResult result = modelnet::SwarmNoteNotNoRefund(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
