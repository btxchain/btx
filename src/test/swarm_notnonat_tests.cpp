// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnonat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotNoNat note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNatResult result = modelnet::SwarmNoteNotNoNat(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_publish_is_no_addr)
{
    modelnet::SwarmNotNoNat note;
    note.peer_id = "peer-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNatResult result = modelnet::SwarmNoteNotNoNat(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NO_ADDR");
    BOOST_CHECK_EQUAL(err, "NO_ADDR");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoNat note;
    note.peer_id = "peer-1";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNatResult result = modelnet::SwarmNoteNotNoNat(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
