// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocrossdedup2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocrossdedup2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_realm_id_is_realm)
{
    modelnet::SwarmNotNoCrossDedup2 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoCrossDedup2Result result = modelnet::SwarmNoteNotNoCrossDedup2(note, err);
    BOOST_CHECK_EQUAL(result.moved, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "REALM");
    BOOST_CHECK_EQUAL(err, "REALM");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoCrossDedup2 note;
    note.realm_id = "realm-1";
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCrossDedup2Result result = modelnet::SwarmNoteNotNoCrossDedup2(note, err);
    BOOST_CHECK_EQUAL(result.moved, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCrossDedup2 note;
    note.realm_id = "realm-1";
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCrossDedup2Result result = modelnet::SwarmNoteNotNoCrossDedup2(note, err);
    BOOST_CHECK_EQUAL(result.moved, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
