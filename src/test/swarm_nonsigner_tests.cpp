// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nonsigner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nonsigner_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_claim)
{
    modelnet::SwarmNonSigner claim;
    claim.claim_id.clear();
    claim.signer = true;
    claim.want_claim = false;
    std::string err;
    const modelnet::SwarmNonSignerResult result = modelnet::SwarmNoteNonSigner(claim, err);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
}

BOOST_AUTO_TEST_CASE(signer_false_want_claim_false)
{
    modelnet::SwarmNonSigner claim;
    claim.claim_id = "note";
    claim.signer = false;
    claim.want_claim = false;
    std::string err;
    const modelnet::SwarmNonSignerResult result = modelnet::SwarmNoteNonSigner(claim, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNER");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNER");
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
}

BOOST_AUTO_TEST_CASE(want_claim_true_signer_true)
{
    modelnet::SwarmNonSigner claim;
    claim.claim_id = "note";
    claim.signer = true;
    claim.want_claim = true;
    std::string err;
    const modelnet::SwarmNonSignerResult result = modelnet::SwarmNoteNonSigner(claim, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
}

BOOST_AUTO_TEST_CASE(signer_true_want_claim_false)
{
    modelnet::SwarmNonSigner claim;
    claim.claim_id = "note";
    claim.signer = true;
    claim.want_claim = false;
    std::string err = "stale";
    const modelnet::SwarmNonSignerResult result = modelnet::SwarmNoteNonSigner(claim, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
}

BOOST_AUTO_TEST_SUITE_END()
