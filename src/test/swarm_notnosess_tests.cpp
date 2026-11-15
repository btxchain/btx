// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosess.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosess_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id)
{
    modelnet::SwarmNotNoSess note;
    std::string err = "stale";
    const modelnet::SwarmNotNoSessResult result = modelnet::SwarmNoteNotNoSess(note, err);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.mtls);
}

BOOST_AUTO_TEST_CASE(want_session)
{
    modelnet::SwarmNotNoSess note;
    note.peer_id = "peer-a";
    note.want_session = true;
    std::string err;
    const modelnet::SwarmNotNoSessResult result = modelnet::SwarmNoteNotNoSess(note, err);
    BOOST_CHECK_EQUAL(result.code, "NO_SESSION");
    BOOST_CHECK_EQUAL(err, "NO_SESSION");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.mtls);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoSess note;
    note.peer_id = "peer-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoSessResult result = modelnet::SwarmNoteNotNoSess(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.mtls);
}

BOOST_AUTO_TEST_SUITE_END()
