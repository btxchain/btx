// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

bool ThroughAdopt(modelnet::SwarmGeneration& gen, std::string& err)
{
    modelnet::SwarmEvolveScoreReport first;
    first.author = "judge-1";
    first.subject = "subject-a";
    first.domain = "coding";
    first.score = 1500;
    first.independent = true;
    first.rotating = true;
    modelnet::SwarmEvolveScoreReport second = first;
    second.author = "judge-2";
    second.domain = "research";
    second.score = 4500;
    modelnet::SwarmEvolveGraduateRequest request;
    return gen.Experience("public_trajectory", "row", err) && gen.Train(err) && gen.Measure(first, err) &&
           gen.Measure(second, err) && gen.Graduate(request, err) && gen.Adopt(err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_continue_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(continue_opens_generation_two_after_adopt_and_pay_stays_local)
{
    modelnet::SwarmGeneration gen("subject-a", "baseline-parent", "coordinator-1");
    std::string err = "prior";
    BOOST_CHECK_EQUAL(gen.Index(), 1);
    BOOST_CHECK(!gen.Continue(err));
    BOOST_CHECK_EQUAL(err, "ADOPT");
    BOOST_CHECK_EQUAL(gen.Index(), 1);

    BOOST_CHECK(!gen.Pay(0, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 0);
    BOOST_CHECK(!gen.Pay(-4, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 0);

    BOOST_REQUIRE(ThroughAdopt(gen, err));
    BOOST_CHECK(err.empty());
    const std::string parent = gen.Parent();
    BOOST_REQUIRE(gen.Pay(10, err));
    BOOST_REQUIRE(gen.Pay(5, err));
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 15);
    BOOST_CHECK_EQUAL(gen.AutomaticSpend(), "0");
    BOOST_CHECK(!gen.Broadcast());

    BOOST_REQUIRE(gen.Continue(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gen.Index(), 2);
    BOOST_CHECK_EQUAL(gen.Parent(), parent);
    BOOST_CHECK(!gen.Adopted());
    BOOST_CHECK(!gen.Trained());
    BOOST_CHECK_EQUAL(gen.ExperienceSize(), 0U);
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 15);
    BOOST_CHECK_EQUAL(gen.AutomaticSpend(), "0");
    BOOST_CHECK(!gen.Broadcast());

    BOOST_REQUIRE(gen.Train(err));
    BOOST_CHECK_EQUAL(gen.Step(), static_cast<uint64_t>(1));
    BOOST_CHECK(!gen.GpuRan());
    BOOST_CHECK(!gen.Train(err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gen.Step(), static_cast<uint64_t>(1));

    BOOST_CHECK(!gen.Continue(err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(gen.Index(), 2);
    BOOST_CHECK_EQUAL(gen.EarnedAtoms(), 15);
    BOOST_CHECK_EQUAL(gen.AutomaticSpend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
