// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminrefund.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_adminrefund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_yields_channel)
{
    modelnet::SwarmAdminRefund channel;
    channel.channel_id.clear();
    channel.admin = false;
    channel.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmAdminRefundResult result = modelnet::SwarmNoteAdminRefund(channel, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(admin_true_want_move_false_yields_held)
{
    modelnet::SwarmAdminRefund channel;
    channel.channel_id = "ch-1";
    channel.admin = true;
    channel.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmAdminRefundResult result = modelnet::SwarmNoteAdminRefund(channel, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_move_true_admin_false_yields_held)
{
    modelnet::SwarmAdminRefund channel;
    channel.channel_id = "ch-1";
    channel.admin = false;
    channel.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmAdminRefundResult result = modelnet::SwarmNoteAdminRefund(channel, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmAdminRefund channel;
    channel.channel_id = "ch-1";
    channel.admin = false;
    channel.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmAdminRefundResult result = modelnet::SwarmNoteAdminRefund(channel, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
