// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimagebind.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_preimagebind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_claim_is_claim)
{
    modelnet::SwarmPreimageBind bind;
    bind.claim_id.clear();
    bind.length = 32;
    bind.signer = true;
    bind.want_claim = false;
    std::string err = "stale";
    const modelnet::SwarmPreimageBindResult result = modelnet::SwarmBindPreimageLocal(bind, err);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(length_16_is_preimage)
{
    modelnet::SwarmPreimageBind bind;
    bind.claim_id = "claim";
    bind.length = 16;
    bind.signer = true;
    bind.want_claim = false;
    std::string err;
    const modelnet::SwarmPreimageBindResult result = modelnet::SwarmBindPreimageLocal(bind, err);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(signer_false_length_32_is_signer)
{
    modelnet::SwarmPreimageBind bind;
    bind.claim_id = "claim";
    bind.length = 32;
    bind.signer = false;
    bind.want_claim = false;
    std::string err;
    const modelnet::SwarmPreimageBindResult result = modelnet::SwarmBindPreimageLocal(bind, err);
    BOOST_CHECK_EQUAL(result.code, "SIGNER");
    BOOST_CHECK_EQUAL(err, "SIGNER");
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(want_claim_signer_length_32_is_held)
{
    modelnet::SwarmPreimageBind bind;
    bind.claim_id = "claim";
    bind.length = 32;
    bind.signer = true;
    bind.want_claim = true;
    std::string err;
    const modelnet::SwarmPreimageBindResult result = modelnet::SwarmBindPreimageLocal(bind, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(noted_when_signer_length_32_want_claim_false)
{
    modelnet::SwarmPreimageBind bind;
    bind.claim_id = "claim";
    bind.length = 32;
    bind.signer = true;
    bind.want_claim = false;
    std::string err = "stale";
    const modelnet::SwarmPreimageBindResult result = modelnet::SwarmBindPreimageLocal(bind, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
