// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_norealmoney.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_norealmoney_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNoRealMoney note;
    note.want_real_money = true;
    const modelnet::SwarmNoRealMoneyResult result = modelnet::SwarmNoteNoRealMoney(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_real_money_is_real_money)
{
    std::string err = "prior";
    modelnet::SwarmNoRealMoney note;
    note.channel_id = "chan-a";
    note.want_real_money = true;
    const modelnet::SwarmNoRealMoneyResult result = modelnet::SwarmNoteNoRealMoney(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "REAL_MONEY");
    BOOST_CHECK_EQUAL(err, "REAL_MONEY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNoRealMoney note;
    note.channel_id = "chan-a";
    note.want_real_money = false;
    const modelnet::SwarmNoRealMoneyResult result = modelnet::SwarmNoteNoRealMoney(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
