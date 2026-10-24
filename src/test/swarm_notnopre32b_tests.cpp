// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopre32b.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopre32b_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_claim)
{
    modelnet::SwarmNotNoPre32b note;
    note.claim_id.clear();
    note.length = 31;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPre32bResult result = modelnet::SwarmNoteNotNoPre32b(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
}

BOOST_AUTO_TEST_CASE(length_31_is_not_claimed)
{
    modelnet::SwarmNotNoPre32b note;
    note.claim_id = "claim-1";
    note.length = 31;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPre32bResult result = modelnet::SwarmNoteNotNoPre32b(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CLAIMED");
    BOOST_CHECK_EQUAL(err, "NOT_CLAIMED");
}

BOOST_AUTO_TEST_CASE(want_claim_length_32_is_held)
{
    modelnet::SwarmNotNoPre32b note;
    note.claim_id = "claim-1";
    note.length = 32;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPre32bResult result = modelnet::SwarmNoteNotNoPre32b(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(quiet_note_length_32_is_noted)
{
    modelnet::SwarmNotNoPre32b note;
    note.claim_id = "claim-1";
    note.length = 32;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPre32bResult result = modelnet::SwarmNoteNotNoPre32b(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
