// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notaes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notaes_tests, BasicTestingSetup)

static modelnet::SwarmNotAes NotedNote()
{
    modelnet::SwarmNotAes note;
    note.realm_id = "realm";
    note.want_seal = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_realm_id_is_realm)
{
    modelnet::SwarmNotAes note = NotedNote();
    note.realm_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotAesResult result = modelnet::SwarmNoteNotAes(note, err);
    BOOST_CHECK(!result.sealed);
    BOOST_CHECK_EQUAL(result.code, "REALM");
    BOOST_CHECK_EQUAL(err, "REALM");
}

BOOST_AUTO_TEST_CASE(empty_realm_id_wins_over_want_seal)
{
    modelnet::SwarmNotAes note = NotedNote();
    note.realm_id.clear();
    note.want_seal = true;
    std::string err = "prior";
    const modelnet::SwarmNotAesResult result = modelnet::SwarmNoteNotAes(note, err);
    BOOST_CHECK(!result.sealed);
    BOOST_CHECK_EQUAL(result.code, "REALM");
    BOOST_CHECK_EQUAL(err, "REALM");
}

BOOST_AUTO_TEST_CASE(want_seal_is_not_sealed)
{
    modelnet::SwarmNotAes note = NotedNote();
    note.want_seal = true;
    std::string err = "prior";
    const modelnet::SwarmNotAesResult result = modelnet::SwarmNoteNotAes(note, err);
    BOOST_CHECK(!result.sealed);
    BOOST_CHECK_EQUAL(result.code, "NOT_SEALED");
    BOOST_CHECK_EQUAL(err, "NOT_SEALED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotAes note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotAesResult result = modelnet::SwarmNoteNotAes(note, err);
    BOOST_CHECK(!result.sealed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
