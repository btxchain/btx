// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_executor.h>
#include <modelnet/swarm_runcycle.h>

#include <crypto/sha256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_runcycle_tests, BasicTestingSetup)

namespace {

uint256 HashOf(const std::vector<unsigned char>& preimage)
{
    uint256 hash;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.begin());
    return hash;
}

} // namespace

BOOST_AUTO_TEST_CASE(form_requires_a_node_and_modelnet)
{
    modelnet::SwarmRunCycle cycle;
    std::string err;
    BOOST_CHECK(!cycle.Form("", true, err));
    BOOST_CHECK_EQUAL(err, "NODE");
    BOOST_CHECK(!cycle.Form("node-a", false, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!cycle.formed());
    BOOST_CHECK(cycle.Form("node-a", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cycle.formed());
    BOOST_CHECK(!cycle.Form("node-a", true, err));
    BOOST_CHECK_EQUAL(err, "REOPEN");
}

BOOST_AUTO_TEST_CASE(admit_enforces_the_sandbox_caps)
{
    modelnet::SwarmExecutorRequest over;
    over.sandbox_present = true;
    over.requested_threads = 65;
    std::string err;
    const modelnet::SwarmExecutorDecision capped = modelnet::SwarmAdmitExecutor(over, err);
    BOOST_CHECK(!capped.admitted);
    BOOST_CHECK(!capped.launched);
    BOOST_CHECK_EQUAL(err, "CAPPED");

    over.requested_threads = 1;
    over.network = true;
    const modelnet::SwarmExecutorDecision networked = modelnet::SwarmAdmitExecutor(over, err);
    BOOST_CHECK(!networked.admitted);
    BOOST_CHECK_EQUAL(err, "NETWORK");

    modelnet::SwarmRunCycle cycle;
    BOOST_REQUIRE(cycle.Form("node-a", true, err));
    BOOST_CHECK(!cycle.Admit("job-1", 65, 1, true, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK(!cycle.Admit("job-1", 1, 1, false, err));
    BOOST_CHECK_EQUAL(err, "SANDBOX_ABSENT");
    BOOST_CHECK(cycle.Admit("job-1", 1, 1, true, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(a_cycle_measures_graduates_adopts_and_pays)
{
    modelnet::SwarmRunCycle cycle;
    std::string err;
    BOOST_REQUIRE(cycle.Form("node-a", true, err));
    BOOST_REQUIRE(cycle.Admit("gen-1", 4, 512, true, err));
    BOOST_CHECK(!cycle.Experience("gen-1", "private_prompt", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE(cycle.Experience("gen-1", "public_trajectory", err));
    BOOST_CHECK(!cycle.Measure("gen-1", false, true, 10, err));
    BOOST_CHECK_EQUAL(err, "TRAIN");
    BOOST_REQUIRE(cycle.TrainJob("gen-1", err));
    BOOST_CHECK_EQUAL(cycle.job_steps("gen-1"), 1U);
    BOOST_CHECK(!cycle.job_state_hash("gen-1").empty());
    BOOST_CHECK(!cycle.Measure("gen-1", true, true, 10, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_CHECK(!cycle.Measure("gen-1", false, false, 10, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_REQUIRE(cycle.Measure("gen-1", false, true, 10, err));
    BOOST_CHECK(!cycle.GraduateJob("gen-1", true, false, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_REQUIRE(cycle.GraduateJob("gen-1", false, false, err));
    BOOST_CHECK(!cycle.AdoptJob("gen-1", false, err));
    BOOST_REQUIRE(cycle.AdoptJob("gen-1", true, err));
    BOOST_CHECK_EQUAL(cycle.active_model(), "gen-1");

    const std::vector<unsigned char> preimage(32, 0x11);
    BOOST_REQUIRE(cycle.PayJob("gen-1", "worker-a", 1000, HashOf(preimage), preimage, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cycle.job_paid("gen-1"));
    BOOST_CHECK_EQUAL(cycle.earned_atoms(), 1000);
    BOOST_REQUIRE(cycle.Recover(err));
    BOOST_CHECK_EQUAL(cycle.earned_atoms(), 1000);
    BOOST_REQUIRE(cycle.ContinueFrom("gen-1", "gen-2", err));
    BOOST_CHECK(!cycle.job_paid("gen-2"));
}

BOOST_AUTO_TEST_SUITE_END()
