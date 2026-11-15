// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno604800.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notno604800_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNotNo604800 note;
    note.want_close = true;
    const modelnet::SwarmNotNo604800Result result = modelnet::SwarmNoteNotNo604800(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_close_is_not_wallclock)
{
    std::string err = "prior";
    modelnet::SwarmNotNo604800 note;
    note.channel_id = "channel-note";
    note.want_close = true;
    const modelnet::SwarmNotNo604800Result result = modelnet::SwarmNoteNotNo604800(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_WALLCLOCK");
    BOOST_CHECK_EQUAL(err, "NOT_WALLCLOCK");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNo604800 note;
    note.channel_id = "channel-note";
    note.want_close = false;
    const modelnet::SwarmNotNo604800Result result = modelnet::SwarmNoteNotNo604800(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
