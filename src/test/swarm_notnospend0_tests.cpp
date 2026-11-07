// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospend0.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnospend0_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSpend0 NotedNote()
{
    modelnet::SwarmNotNoSpend0 note;
    note.mandate_id = "mandate-1";
    note.spend_atoms = 0;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_mandate_id_is_mandate)
{
    modelnet::SwarmNotNoSpend0 note = NotedNote();
    note.mandate_id.clear();
    note.spend_atoms = 1;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpend0Result result = modelnet::SwarmNoteNotNoSpend0(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");
}

BOOST_AUTO_TEST_CASE(nonzero_spend_atoms_is_held)
{
    modelnet::SwarmNotNoSpend0 note = NotedNote();
    note.spend_atoms = 1;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpend0Result result = modelnet::SwarmNoteNotNoSpend0(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_spend_is_held)
{
    modelnet::SwarmNotNoSpend0 note = NotedNote();
    note.spend_atoms = 0;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpend0Result result = modelnet::SwarmNoteNotNoSpend0(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_zero_is_noted)
{
    modelnet::SwarmNotNoSpend0 note = NotedNote();
    note.spend_atoms = 0;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpend0Result result = modelnet::SwarmNoteNotNoSpend0(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
