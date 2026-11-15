// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrustckpt2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotrustckpt2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_claim_id_is_claim)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTrustCkpt2 note;
    note.checkpoint_only = true;
    note.want_trust = true;
    const modelnet::SwarmNotNoTrustCkpt2Result result = modelnet::SwarmNoteNotNoTrustCkpt2(note, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
}

BOOST_AUTO_TEST_CASE(checkpoint_only_is_not_trust_even_when_want_trust_is_false)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTrustCkpt2 note;
    note.claim_id = "claim-ckpt";
    note.checkpoint_only = true;
    note.want_trust = false;
    const modelnet::SwarmNotNoTrustCkpt2Result result = modelnet::SwarmNoteNotNoTrustCkpt2(note, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRUST");
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
}

BOOST_AUTO_TEST_CASE(want_trust_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTrustCkpt2 note;
    note.claim_id = "claim-ckpt";
    note.checkpoint_only = false;
    note.want_trust = true;
    const modelnet::SwarmNotNoTrustCkpt2Result result = modelnet::SwarmNoteNotNoTrustCkpt2(note, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_claim_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTrustCkpt2 note;
    note.claim_id = "claim-ckpt";
    note.checkpoint_only = false;
    note.want_trust = false;
    const modelnet::SwarmNotNoTrustCkpt2Result result = modelnet::SwarmNoteNotNoTrustCkpt2(note, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
