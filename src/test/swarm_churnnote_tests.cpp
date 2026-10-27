// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_churnnote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_churnnote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer)
{
    modelnet::SwarmChurnNote note;
    note.peer_id.clear();
    note.churned = false;
    note.want_send = false;
    std::string err;
    const modelnet::SwarmChurnNoteResult result = modelnet::SwarmNoteChurn(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(churned_want_send_false)
{
    modelnet::SwarmChurnNote note;
    note.peer_id = "peer-a";
    note.churned = true;
    note.want_send = false;
    std::string err;
    const modelnet::SwarmChurnNoteResult result = modelnet::SwarmNoteChurn(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "CHURNED");
    BOOST_CHECK_EQUAL(err, "CHURNED");
}

BOOST_AUTO_TEST_CASE(want_send_held)
{
    modelnet::SwarmChurnNote note;
    note.peer_id = "peer-b";
    note.churned = false;
    note.want_send = true;
    std::string err;
    const modelnet::SwarmChurnNoteResult result = modelnet::SwarmNoteChurn(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmChurnNote note;
    note.peer_id = "peer-c";
    note.churned = false;
    note.want_send = false;
    std::string err = "stale";
    const modelnet::SwarmChurnNoteResult result = modelnet::SwarmNoteChurn(note, err);
    BOOST_CHECK(!result.sent);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
