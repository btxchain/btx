// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_generation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generation_two_trains_and_recover_keeps_earned_atoms)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    modelnet::SwarmGeneration gen("subject-a", "baseline-parent", "coordinator-1");
    std::string err = "prior";
    BOOST_REQUIRE(gen.Experience("public_trajectory", "traj-1", err));
    BOOST_REQUIRE(gen.Train(err));
    BOOST_CHECK_EQUAL(gen.Step(), static_cast<uint64_t>(1));
    BOOST_CHECK(!gen.GpuRan());
    BOOST_REQUIRE(gen.State().step == 1);
    modelnet::IntegerTrainer check;
    BOOST_REQUIRE(check.ReplayMatches(gen.State(), err));

    modelnet::SwarmEvolveScoreReport first;
    first.author = "judge-1";
    first.subject = "subject-a";
    first.domain = "coding";
    first.score = 1000;
    first.independent = true;
    first.rotating = true;
    modelnet::SwarmEvolveScoreReport second = first;
    second.author = "judge-2";
    second.domain = "research";
    second.score = 5000;
    BOOST_REQUIRE(gen.Measure(first, err));
    BOOST_REQUIRE(gen.Measure(second, err));
    BOOST_REQUIRE(gen.MeasureAccepted());
    BOOST_REQUIRE_EQUAL(gen.Scores().size(), 2U);
    BOOST_CHECK_EQUAL(gen.Scores()[0], 1000);
    BOOST_CHECK_EQUAL(gen.Scores()[1], 5000);

    modelnet::SwarmEvolveGraduateRequest request;
    BOOST_REQUIRE(gen.Graduate(request, err));
    BOOST_REQUIRE(gen.Graduated());
    BOOST_CHECK(!gen.RealmPromoted());
    BOOST_CHECK(!gen.ExactReplayAdmitted());
    const std::string graduated = gen.GraduatedId();
    BOOST_REQUIRE(!graduated.empty());

    BOOST_REQUIRE(gen.Adopt(err));
    BOOST_CHECK_EQUAL(gen.Parent(), graduated);
    BOOST_REQUIRE(gen.Pay(42, err));
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 42);
    BOOST_CHECK_EQUAL(gen.AutomaticSpend(), "0");
    BOOST_CHECK(!gen.Broadcast());

    BOOST_REQUIRE(gen.Continue(err));
    BOOST_CHECK_EQUAL(gen.Index(), 2);
    BOOST_CHECK_EQUAL(gen.Parent(), graduated);
    BOOST_REQUIRE(gen.Train(err));
    BOOST_CHECK_EQUAL(gen.Step(), static_cast<uint64_t>(1));
    BOOST_CHECK(!gen.StateHash().empty());
    BOOST_CHECK(!gen.GpuRan());
    BOOST_CHECK(!gen.ExactReplayAdmitted());

    const int64_t earned = gen.EarnedAtoms();
    BOOST_REQUIRE(gen.Recover(err));
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), earned);
    BOOST_CHECK_EQUAL(earned, 42);
    BOOST_CHECK(gen.CoordinatorId().empty());
    BOOST_CHECK_EQUAL(gen.BytesMoved(), 0);
    BOOST_CHECK(!gen.Mined());
    BOOST_CHECK_EQUAL(gen.AutomaticSpend(), "0");
    BOOST_CHECK(!gen.Broadcast());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_SUITE_END()
