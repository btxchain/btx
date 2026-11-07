// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprivateoff.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notprivateoff_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotPrivateOff note;
    note.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmNotPrivateOffResult result = modelnet::SwarmNoteNotPrivateOff(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_private_is_private_off)
{
    modelnet::SwarmNotPrivateOff note;
    note.node_id = "node-1";
    note.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmNotPrivateOffResult result = modelnet::SwarmNoteNotPrivateOff(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.code, "PRIVATE_OFF");
    BOOST_CHECK_EQUAL(err, "PRIVATE_OFF");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotPrivateOff note;
    note.node_id = "node-1";
    note.want_private = false;
    std::string err = "prior";
    const modelnet::SwarmNotPrivateOffResult result = modelnet::SwarmNoteNotPrivateOff(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
