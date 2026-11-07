// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosignerkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosignerkey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_claim_id_is_claim)
{
    modelnet::SwarmNotNoSignerKey note;
    note.claim_id.clear();
    note.not_signer = false;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSignerKeyResult result = modelnet::SwarmNoteNotNoSignerKey(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
}

BOOST_AUTO_TEST_CASE(not_signer_is_not_signer)
{
    modelnet::SwarmNotNoSignerKey note;
    note.claim_id = "claim-1";
    note.not_signer = true;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSignerKeyResult result = modelnet::SwarmNoteNotNoSignerKey(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNER");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNER");
}

BOOST_AUTO_TEST_CASE(want_claim_is_held)
{
    modelnet::SwarmNotNoSignerKey note;
    note.claim_id = "claim-1";
    note.not_signer = false;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSignerKeyResult result = modelnet::SwarmNoteNotNoSignerKey(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_is_noted)
{
    modelnet::SwarmNotNoSignerKey note;
    note.claim_id = "claim-1";
    note.not_signer = false;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSignerKeyResult result = modelnet::SwarmNoteNotNoSignerKey(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
