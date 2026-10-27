// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp28/grp28.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <modelnet/swarm_evalengine/codes.h>
#include <modelnet/swarm_paycycle/codes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

void Qualify(modelnet::Grp28& eng, const std::string& candidate)
{
    std::string err;
    BOOST_REQUIRE(eng.OpenExperiment("exp", err));
    BOOST_REQUIRE(eng.BindCandidate("exp", candidate, err));
    BOOST_REQUIRE(eng.CommitSuite("exp", "suite", err));
    BOOST_REQUIRE(eng.Report("exp", candidate, "writer-a", "reader-a", "side-a", "side-b", false, false, false, err));
    BOOST_REQUIRE(eng.Report("exp", candidate, "writer-c", "reader-c", "side-c", "side-d", false, false, false, err));
}

void Idle(modelnet::Grp28& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp28_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(promote_before_qualification_is_not_graduated)
{
    modelnet::Grp28 eng;
    std::string err = "prior";
    BOOST_CHECK(!eng.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmEvaluationNotGraduated);
    BOOST_CHECK(!eng.promoted("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Stage("chan", "cand", modelnet::kSwarmEvaluationPolicyFollow, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmEvaluationNotGraduated);
    BOOST_CHECK(eng.staged("chan").empty());
    BOOST_CHECK(eng.active("chan").empty());
    BOOST_CHECK(!eng.Adopt("chan", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmEvaluationNotStaged);
    BOOST_CHECK_EQUAL(eng.adoption_count("chan"), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(stage_uses_the_engine_and_adopt_is_separate)
{
    modelnet::Grp28 eng;
    std::string err = "prior";
    Qualify(eng, "cand");
    BOOST_REQUIRE(eng.Promote("cand", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.promoted("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Adopt("chan", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmEvaluationNotStaged);
    BOOST_CHECK(eng.active("chan").empty());
    BOOST_REQUIRE(eng.Stage("chan", "cand", modelnet::kSwarmEvaluationPolicyFollow, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.staged("chan"), "cand");
    BOOST_CHECK(eng.active("chan").empty());
    BOOST_CHECK_EQUAL(eng.adoption_count("chan"), static_cast<std::size_t>(0));
    BOOST_REQUIRE(eng.Adopt("chan", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.active("chan"), "cand");
    BOOST_CHECK(eng.staged("chan").empty());
    BOOST_CHECK_EQUAL(eng.adoption_count("chan"), static_cast<std::size_t>(1));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(settle_stays_unqualified)
{
    modelnet::Grp28 eng;
    std::string err = "prior";
    BOOST_CHECK(!eng.Settle(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(pay_stays_held_and_moves_no_atoms)
{
    modelnet::Grp28 eng;
    std::string err = "prior";
    BOOST_CHECK(!eng.OpenChannel("chan", "pool-a", "pool-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::SWARM_ECONOMYCLASS_ECONOMY);
    BOOST_REQUIRE(eng.OpenChannel("chan", "pool-a", "pool-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.PayWork("pool-a", "job-a", "worker-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::SWARM_PAYCYCLE_HELD);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Settle(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
