// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobalance.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnobalance_tests, BasicTestingSetup)

static modelnet::SwarmNotNoBalance NotedNote()
{
    modelnet::SwarmNotNoBalance note;
    note.ledger_id = "ledger-1";
    note.mixed_books = false;
    note.want_combine = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_ledger_id_is_ledger)
{
    modelnet::SwarmNotNoBalance note = NotedNote();
    note.ledger_id.clear();
    note.mixed_books = true;
    note.want_combine = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBalanceResult result = modelnet::SwarmNoteNotNoBalance(note, err);
    BOOST_CHECK(!result.combined);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(mixed_books_is_separate)
{
    modelnet::SwarmNotNoBalance note = NotedNote();
    note.mixed_books = true;
    note.want_combine = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBalanceResult result = modelnet::SwarmNoteNotNoBalance(note, err);
    BOOST_CHECK(!result.combined);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(want_combine_is_held)
{
    modelnet::SwarmNotNoBalance note = NotedNote();
    note.mixed_books = false;
    note.want_combine = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBalanceResult result = modelnet::SwarmNoteNotNoBalance(note, err);
    BOOST_CHECK(!result.combined);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoBalance note = NotedNote();
    note.mixed_books = false;
    note.want_combine = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBalanceResult result = modelnet::SwarmNoteNotNoBalance(note, err);
    BOOST_CHECK(!result.combined);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
