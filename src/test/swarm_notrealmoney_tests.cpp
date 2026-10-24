// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrealmoney.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrealmoney_tests, BasicTestingSetup)

static modelnet::SwarmNotRealMoney NotedNote()
{
    modelnet::SwarmNotRealMoney note;
    note.channel_id = "channel-1";
    note.want_open = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotRealMoney note = NotedNote();
    note.channel_id.clear();
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotRealMoneyResult result = modelnet::SwarmNoteNotRealMoney(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.funded);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_open_is_real_money)
{
    modelnet::SwarmNotRealMoney note = NotedNote();
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotRealMoneyResult result = modelnet::SwarmNoteNotRealMoney(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.funded);
    BOOST_CHECK_EQUAL(result.code, "REAL_MONEY");
    BOOST_CHECK_EQUAL(err, "REAL_MONEY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRealMoney note = NotedNote();
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotRealMoneyResult result = modelnet::SwarmNoteNotRealMoney(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.funded);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
