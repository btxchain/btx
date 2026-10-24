// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospend02.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnospend02_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSpend02 NotedNote()
{
    modelnet::SwarmNotNoSpend02 note;
    note.wallet_id = "wallet-1";
    note.want_arm = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_wallet_id_is_wallet)
{
    modelnet::SwarmNotNoSpend02 note = NotedNote();
    note.wallet_id.clear();
    note.want_arm = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpend02Result result = modelnet::SwarmNoteNotNoSpend02(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "WALLET");
    BOOST_CHECK_EQUAL(err, "WALLET");
}

BOOST_AUTO_TEST_CASE(want_arm_is_held)
{
    modelnet::SwarmNotNoSpend02 note = NotedNote();
    note.want_arm = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpend02Result result = modelnet::SwarmNoteNotNoSpend02(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSpend02 note = NotedNote();
    note.want_arm = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpend02Result result = modelnet::SwarmNoteNotNoSpend02(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
