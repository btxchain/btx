// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospendkey2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnospendkey2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_key_id_is_key)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpendKey2 note;
    note.research = true;
    note.want_arm = true;
    const modelnet::SwarmNotNoSpendKey2Result result = modelnet::SwarmNoteNotNoSpendKey2(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(research_without_want_arm_is_not_spend)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpendKey2 note;
    note.key_id = "key-1";
    note.research = true;
    note.want_arm = false;
    const modelnet::SwarmNotNoSpendKey2Result result = modelnet::SwarmNoteNotNoSpendKey2(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_SPEND");
    BOOST_CHECK_EQUAL(err, "NOT_SPEND");
}

BOOST_AUTO_TEST_CASE(want_arm_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpendKey2 note;
    note.key_id = "key-1";
    note.research = false;
    note.want_arm = true;
    const modelnet::SwarmNotNoSpendKey2Result result = modelnet::SwarmNoteNotNoSpendKey2(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpendKey2 note;
    note.key_id = "key-1";
    note.research = false;
    note.want_arm = false;
    const modelnet::SwarmNotNoSpendKey2Result result = modelnet::SwarmNoteNotNoSpendKey2(note, err);
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
