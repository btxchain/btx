// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoseal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_realm_id_is_realm)
{
    modelnet::SwarmNotNoSeal note;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealResult result = modelnet::SwarmNoteNotNoSeal(note, err);
    BOOST_CHECK_EQUAL(result.sealed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "REALM");
    BOOST_CHECK_EQUAL(err, "REALM");
}

BOOST_AUTO_TEST_CASE(want_seal_is_not_sealed)
{
    modelnet::SwarmNotNoSeal note;
    note.realm_id = "realm";
    note.want_seal = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealResult result = modelnet::SwarmNoteNotNoSeal(note, err);
    BOOST_CHECK_EQUAL(result.sealed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_SEALED");
    BOOST_CHECK_EQUAL(err, "NOT_SEALED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSeal note;
    note.realm_id = "realm";
    note.want_seal = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealResult result = modelnet::SwarmNoteNotNoSeal(note, err);
    BOOST_CHECK_EQUAL(result.sealed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
