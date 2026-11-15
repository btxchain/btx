// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notautospend.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notautospend_tests, BasicTestingSetup)

static modelnet::SwarmNotAutospend NotedNote()
{
    modelnet::SwarmNotAutospend note;
    note.wallet_id = "wallet-1";
    note.automatic_spend_atoms = "0";
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_wallet_id_is_wallet)
{
    modelnet::SwarmNotAutospend note = NotedNote();
    note.wallet_id.clear();
    note.automatic_spend_atoms = "1";
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotAutospendResult result = modelnet::SwarmNoteNotAutospend(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "WALLET");
    BOOST_CHECK_EQUAL(err, "WALLET");
}

BOOST_AUTO_TEST_CASE(atoms_one_is_held)
{
    modelnet::SwarmNotAutospend note = NotedNote();
    note.automatic_spend_atoms = "1";
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotAutospendResult result = modelnet::SwarmNoteNotAutospend(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(empty_atoms_is_held)
{
    modelnet::SwarmNotAutospend note = NotedNote();
    note.automatic_spend_atoms.clear();
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotAutospendResult result = modelnet::SwarmNoteNotAutospend(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_spend_is_held)
{
    modelnet::SwarmNotAutospend note = NotedNote();
    note.automatic_spend_atoms = "0";
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotAutospendResult result = modelnet::SwarmNoteNotAutospend(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_zero_atoms_is_noted)
{
    modelnet::SwarmNotAutospend note = NotedNote();
    note.automatic_spend_atoms = "0";
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotAutospendResult result = modelnet::SwarmNoteNotAutospend(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
