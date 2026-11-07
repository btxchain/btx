// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonatpub2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnonatpub2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNatPub2 note;
    note.want_publish = true;
    const modelnet::SwarmNotNoNatPub2Result result = modelnet::SwarmNoteNotNoNatPub2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNatPub2 note;
    note.node_id = "node-1";
    note.want_publish = true;
    const modelnet::SwarmNotNoNatPub2Result result = modelnet::SwarmNoteNotNoNatPub2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNatPub2 note;
    note.node_id = "node-1";
    note.want_publish = false;
    const modelnet::SwarmNotNoNatPub2Result result = modelnet::SwarmNoteNotNoNatPub2(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
