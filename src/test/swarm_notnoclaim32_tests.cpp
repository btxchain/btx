// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclaim32.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclaim32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_claim_id_is_claim)
{
    modelnet::SwarmNotNoClaim32 note;
    note.claim_id.clear();
    note.bad_length = true;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoClaim32Result result = modelnet::SwarmNoteNotNoClaim32(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
}

BOOST_AUTO_TEST_CASE(bad_length_is_not_claimed)
{
    modelnet::SwarmNotNoClaim32 note;
    note.claim_id = "claim-1";
    note.bad_length = true;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoClaim32Result result = modelnet::SwarmNoteNotNoClaim32(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CLAIMED");
    BOOST_CHECK_EQUAL(err, "NOT_CLAIMED");
}

BOOST_AUTO_TEST_CASE(want_claim_is_held)
{
    modelnet::SwarmNotNoClaim32 note;
    note.claim_id = "claim-1";
    note.bad_length = false;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoClaim32Result result = modelnet::SwarmNoteNotNoClaim32(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_is_noted)
{
    modelnet::SwarmNotNoClaim32 note;
    note.claim_id = "claim-1";
    note.bad_length = false;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoClaim32Result result = modelnet::SwarmNoteNotNoClaim32(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
