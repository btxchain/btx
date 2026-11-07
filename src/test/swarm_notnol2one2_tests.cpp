// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnol2one2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnol2one2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoL2One2 note;
    note.channel_id.clear();
    note.many_pools = true;
    note.want_split = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2One2Result result = modelnet::SwarmNoteNotNoL2One2(note, err);
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(many_pools_is_stays)
{
    modelnet::SwarmNotNoL2One2 note;
    note.channel_id = "channel-1";
    note.many_pools = true;
    note.want_split = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2One2Result result = modelnet::SwarmNoteNotNoL2One2(note, err);
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(result.code, "STAYS");
    BOOST_CHECK_EQUAL(err, "STAYS");
}

BOOST_AUTO_TEST_CASE(want_split_is_held)
{
    modelnet::SwarmNotNoL2One2 note;
    note.channel_id = "channel-1";
    note.many_pools = false;
    note.want_split = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2One2Result result = modelnet::SwarmNoteNotNoL2One2(note, err);
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoL2One2 note;
    note.channel_id = "channel-1";
    note.many_pools = false;
    note.want_split = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2One2Result result = modelnet::SwarmNoteNotNoL2One2(note, err);
    BOOST_CHECK(!result.split);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
