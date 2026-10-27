// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopinpub.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopinpub_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPinPub note;
    note.pin_member = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoPinPubResult result = modelnet::SwarmNoteNotNoPinPub(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(pin_member)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPinPub note;
    note.node_id = "node-1";
    note.pin_member = true;
    note.want_publish = false;
    const modelnet::SwarmNotNoPinPubResult result = modelnet::SwarmNoteNotNoPinPub(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPinPub note;
    note.node_id = "node-1";
    note.pin_member = false;
    note.want_publish = true;
    const modelnet::SwarmNotNoPinPubResult result = modelnet::SwarmNoteNotNoPinPub(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPinPub note;
    note.node_id = "node-1";
    note.pin_member = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoPinPubResult result = modelnet::SwarmNoteNotNoPinPub(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.authority);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
