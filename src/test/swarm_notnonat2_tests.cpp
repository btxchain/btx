// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonat2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnonat2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotNoNat2 note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNat2Result result = modelnet::SwarmNoteNotNoNat2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_publish_is_not_published)
{
    modelnet::SwarmNotNoNat2 note;
    note.peer_id = "peer-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNat2Result result = modelnet::SwarmNoteNotNoNat2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_PUBLISHED");
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoNat2 note;
    note.peer_id = "peer-1";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNat2Result result = modelnet::SwarmNoteNotNoNat2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
