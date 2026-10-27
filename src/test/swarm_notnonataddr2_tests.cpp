// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonataddr2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnonataddr2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNatAddr2 note;
    note.nat = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoNatAddr2Result result = modelnet::SwarmNoteNotNoNatAddr2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(nat_is_not_published)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNatAddr2 note;
    note.peer_id = "peer-1";
    note.nat = true;
    note.want_publish = false;
    const modelnet::SwarmNotNoNatAddr2Result result = modelnet::SwarmNoteNotNoNatAddr2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOT_PUBLISHED");
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNatAddr2 note;
    note.peer_id = "peer-1";
    note.nat = false;
    note.want_publish = true;
    const modelnet::SwarmNotNoNatAddr2Result result = modelnet::SwarmNoteNotNoNatAddr2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNatAddr2 note;
    note.peer_id = "peer-1";
    note.nat = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoNatAddr2Result result = modelnet::SwarmNoteNotNoNatAddr2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
