// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notchurn.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notchurn_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotChurn note;
    std::string err = "prior";
    const modelnet::SwarmNotChurnResult result = modelnet::SwarmNoteNotChurn(note, err);
    BOOST_CHECK_EQUAL(result.recovered, false);
    BOOST_CHECK_EQUAL(result.restarted, false);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_recover_is_not_observed)
{
    modelnet::SwarmNotChurn note;
    note.peer_id = "peer-1";
    note.want_recover = true;
    std::string err = "prior";
    const modelnet::SwarmNotChurnResult result = modelnet::SwarmNoteNotChurn(note, err);
    BOOST_CHECK_EQUAL(result.recovered, false);
    BOOST_CHECK_EQUAL(result.restarted, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_OBSERVED");
    BOOST_CHECK_EQUAL(err, "NOT_OBSERVED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotChurn note;
    note.peer_id = "peer-1";
    note.want_recover = false;
    std::string err = "prior";
    const modelnet::SwarmNotChurnResult result = modelnet::SwarmNoteNotChurn(note, err);
    BOOST_CHECK_EQUAL(result.recovered, false);
    BOOST_CHECK_EQUAL(result.restarted, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
