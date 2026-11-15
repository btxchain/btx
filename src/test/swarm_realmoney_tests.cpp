// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_realmoney.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_realmoney_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmRealMoney channel;
    channel.real_money = true;
    channel.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmRealMoneyResult result = modelnet::SwarmNoteRealMoney(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(real_money_is_not_opened_when_want_open_is_false)
{
    modelnet::SwarmRealMoney channel;
    channel.channel_id = "channel-1";
    channel.real_money = true;
    channel.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmRealMoneyResult result = modelnet::SwarmNoteRealMoney(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPENED");
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmRealMoney channel;
    channel.channel_id = "channel-1";
    channel.real_money = false;
    channel.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmRealMoneyResult result = modelnet::SwarmNoteRealMoney(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmRealMoney channel;
    channel.channel_id = "channel-1";
    channel.real_money = false;
    channel.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmRealMoneyResult result = modelnet::SwarmNoteRealMoney(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
