// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochurn2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnochurn2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn2 note;
    note.churned = true;
    note.want_send = true;
    const modelnet::SwarmNotNoChurn2Result result = modelnet::SwarmNoteNotNoChurn2(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(churned)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn2 note;
    note.peer_id = "peer-1";
    note.churned = true;
    note.want_send = false;
    const modelnet::SwarmNotNoChurn2Result result = modelnet::SwarmNoteNotNoChurn2(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SENT");
    BOOST_CHECK_EQUAL(err, "NOT_SENT");
}

BOOST_AUTO_TEST_CASE(want_send)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn2 note;
    note.peer_id = "peer-1";
    note.churned = false;
    note.want_send = true;
    const modelnet::SwarmNotNoChurn2Result result = modelnet::SwarmNoteNotNoChurn2(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn2 note;
    note.peer_id = "peer-1";
    note.churned = false;
    note.want_send = false;
    const modelnet::SwarmNotNoChurn2Result result = modelnet::SwarmNoteNotNoChurn2(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
