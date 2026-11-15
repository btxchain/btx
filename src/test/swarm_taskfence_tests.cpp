// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_taskfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_taskfence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(claim_binds_a_running_task)
{
    modelnet::SwarmTaskClaim claim;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmClaimTask(claim, "", "worker", 1, 1, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(claim.state == modelnet::SwarmTaskState::Queued);

    BOOST_CHECK(!modelnet::SwarmClaimTask(claim, "task", "", 1, 1, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!modelnet::SwarmClaimTask(claim, "task", "worker", -1, 1, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!modelnet::SwarmClaimTask(claim, "task", "worker", 1, -1, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");

    BOOST_REQUIRE(modelnet::SwarmClaimTask(claim, "task", "worker", 3, 4, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(claim.task_id, "task");
    BOOST_CHECK_EQUAL(claim.worker_id, "worker");
    BOOST_CHECK_EQUAL(claim.term, 3);
    BOOST_CHECK_EQUAL(claim.generation, 4);
    BOOST_CHECK(claim.state == modelnet::SwarmTaskState::Running);
    BOOST_CHECK(!claim.result_kept);
}

BOOST_AUTO_TEST_CASE(stale_term_leaves_the_claim)
{
    modelnet::SwarmTaskClaim claim;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmClaimTask(claim, "task", "worker", 5, 1, err));
    BOOST_CHECK(!modelnet::SwarmAdvanceTerm(claim, 5, err));
    BOOST_CHECK_EQUAL(err, "STALE_TERM");
    BOOST_CHECK_EQUAL(claim.term, 5);
    BOOST_CHECK(claim.state == modelnet::SwarmTaskState::Running);

    BOOST_CHECK(!modelnet::SwarmAdvanceTerm(claim, 4, err));
    BOOST_CHECK_EQUAL(err, "STALE_TERM");
    BOOST_CHECK_EQUAL(claim.term, 5);
    BOOST_CHECK(claim.state == modelnet::SwarmTaskState::Running);
    BOOST_CHECK(!claim.result_kept);
}

BOOST_AUTO_TEST_CASE(advance_requeues_running_and_keeps_result_kept)
{
    modelnet::SwarmTaskClaim claim;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmClaimTask(claim, "task", "worker", 2, 7, err));
    claim.result_kept = true;
    BOOST_REQUIRE(modelnet::SwarmAdvanceTerm(claim, 3, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(claim.term, 3);
    BOOST_CHECK_EQUAL(claim.generation, 7);
    BOOST_CHECK(claim.state == modelnet::SwarmTaskState::Queued);
    BOOST_CHECK(claim.result_kept);

    modelnet::SwarmTaskClaim fresh;
    BOOST_REQUIRE(modelnet::SwarmClaimTask(fresh, "task", "worker", 1, 0, err));
    BOOST_REQUIRE(modelnet::SwarmAdvanceTerm(fresh, 2, err));
    BOOST_CHECK(fresh.state == modelnet::SwarmTaskState::Queued);
    BOOST_CHECK(!fresh.result_kept);
}

BOOST_AUTO_TEST_CASE(cancel_keeps_result_kept)
{
    modelnet::SwarmTaskClaim empty;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmCancelTask(empty, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(empty.state == modelnet::SwarmTaskState::Queued);
    BOOST_CHECK(!empty.result_kept);

    modelnet::SwarmTaskClaim claim;
    BOOST_REQUIRE(modelnet::SwarmClaimTask(claim, "task", "worker", 1, 2, err));
    claim.result_kept = true;
    BOOST_REQUIRE(modelnet::SwarmCancelTask(claim, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(claim.task_id, "task");
    BOOST_CHECK_EQUAL(claim.worker_id, "worker");
    BOOST_CHECK_EQUAL(claim.term, 1);
    BOOST_CHECK_EQUAL(claim.generation, 2);
    BOOST_CHECK(claim.state == modelnet::SwarmTaskState::Cancelled);
    BOOST_CHECK(claim.result_kept);
}

BOOST_AUTO_TEST_CASE(unsecured_without_acceptance_is_conservation)
{
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAcceptUnsecured(true, false, "terms", err));
    BOOST_CHECK_EQUAL(err, "CONSERVATION");
    BOOST_CHECK(!modelnet::SwarmAcceptUnsecured(true, false, "", err));
    BOOST_CHECK_EQUAL(err, "CONSERVATION");
}

BOOST_AUTO_TEST_CASE(unsecured_with_acceptance_and_empty_terms_is_terms)
{
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAcceptUnsecured(true, true, "", err));
    BOOST_CHECK_EQUAL(err, "TERMS");

    BOOST_CHECK(modelnet::SwarmAcceptUnsecured(true, true, "terms-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::SwarmAcceptUnsecured(false, false, "", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
