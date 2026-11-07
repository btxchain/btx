// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfourbal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfourbal_tests, BasicTestingSetup)

static modelnet::SwarmNotFourBal NotedNote()
{
    modelnet::SwarmNotFourBal note;
    note.ledger_id = "ledger-1";
    note.want_merge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_ledger_id_is_ledger)
{
    modelnet::SwarmNotFourBal note = NotedNote();
    note.ledger_id.clear();
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotFourBalResult result = modelnet::SwarmNoteNotFourBal(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(want_merge_is_separate)
{
    modelnet::SwarmNotFourBal note = NotedNote();
    note.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmNotFourBalResult result = modelnet::SwarmNoteNotFourBal(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotFourBal note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotFourBalResult result = modelnet::SwarmNoteNotFourBal(note, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
