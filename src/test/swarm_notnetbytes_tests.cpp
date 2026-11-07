// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnetbytes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnetbytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    std::string err = "prior";
    modelnet::SwarmNotNetBytes note;
    note.want_publish = true;
    const modelnet::SwarmNotNetBytesResult result = modelnet::SwarmNoteNotNetBytes(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.nbytes, 0);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotNetBytes note;
    note.peer_id = "peer-netbytes";
    note.want_publish = true;
    const modelnet::SwarmNotNetBytesResult result = modelnet::SwarmNoteNotNetBytes(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.nbytes, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNetBytes note;
    note.peer_id = "peer-netbytes";
    note.want_publish = false;
    const modelnet::SwarmNotNetBytesResult result = modelnet::SwarmNoteNotNetBytes(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.nbytes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
