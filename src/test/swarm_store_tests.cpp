// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cas.h>
#include <modelnet/swarm_executor.h>
#include <modelnet/swarm_seal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_seal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ciphertext_is_not_decrypted_and_private_data_is_not_published)
{
    std::string err;
    modelnet::SwarmSealedPiece sealed;
    sealed.piece_id = "p";
    sealed.realm_id = "r";
    sealed.ciphertext = true;
    const modelnet::SwarmSealResult locked = modelnet::SwarmAcceptSealedPiece(sealed, err);
    BOOST_CHECK(!locked.stored);
    BOOST_CHECK(!locked.decrypted);
    BOOST_CHECK(!locked.bytes_moved);
    BOOST_CHECK_EQUAL(locked.code, "REALM_SEALED");

    modelnet::SwarmSealedPiece priv = sealed;
    priv.ciphertext = false;
    priv.private_record = true;
    const modelnet::SwarmSealResult hidden = modelnet::SwarmAcceptSealedPiece(priv, err);
    BOOST_CHECK(!hidden.stored);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");

    modelnet::SwarmSealedPiece pub = priv;
    pub.private_record = false;
    const modelnet::SwarmSealResult open = modelnet::SwarmAcceptSealedPiece(pub, err);
    BOOST_CHECK(open.stored);
    BOOST_CHECK(!open.decrypted);
    BOOST_CHECK(!open.bytes_moved);

    BOOST_CHECK(!modelnet::SwarmPublishDiscovery(false, true, false, false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(modelnet::SwarmPublishDiscovery(false, false, false, false, err));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(swarm_cas_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(an_invalid_eviction_deletes_nothing)
{
    modelnet::SwarmCasPlan plan;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmCommitCas(plan, true, err));
    BOOST_CHECK_EQUAL(err, "EVICTION");
    BOOST_CHECK(!plan.index_committed);
    BOOST_CHECK(!plan.orphan_deleted);
    BOOST_CHECK(!plan.bytes_trusted);

    plan.eviction_valid = true;
    BOOST_REQUIRE(modelnet::SwarmCommitCas(plan, false, err));
    BOOST_CHECK(plan.index_committed);
    BOOST_CHECK(!plan.orphan_deleted);

    BOOST_REQUIRE(modelnet::SwarmCommitCas(plan, true, err));
    BOOST_CHECK(plan.index_committed);
    BOOST_CHECK(plan.orphan_deleted);
    BOOST_CHECK(!plan.bytes_trusted);

    BOOST_CHECK(!modelnet::SwarmTrustIncomplete(false, err));
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
    BOOST_CHECK(modelnet::SwarmTrustIncomplete(true, err));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(swarm_executor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_remote_manifest_does_not_start_a_host_interpreter)
{
    modelnet::SwarmExecutorRequest request;
    request.remote_manifest = true;
    request.selects_host_interpreter = true;
    std::string err;
    const modelnet::SwarmExecutorDecision refused = modelnet::SwarmAdmitExecutor(request, err);
    BOOST_CHECK(!refused.admitted);
    BOOST_CHECK(!refused.launched);
    BOOST_CHECK_EQUAL(err, "EXECUTOR");

    request.selects_host_interpreter = false;
    const modelnet::SwarmExecutorDecision unsandboxed = modelnet::SwarmAdmitExecutor(request, err);
    BOOST_CHECK(!unsandboxed.admitted);
    BOOST_CHECK(!unsandboxed.launched);
    BOOST_CHECK_EQUAL(err, "SANDBOX_ABSENT");

    request.sandbox_present = true;
    const modelnet::SwarmExecutorDecision admitted = modelnet::SwarmAdmitExecutor(request, err);
    BOOST_CHECK(admitted.admitted);
    BOOST_CHECK(!admitted.launched);
}

BOOST_AUTO_TEST_SUITE_END()
