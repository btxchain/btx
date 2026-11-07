// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

modelnet::SwarmGeneration Ready(const std::string& parent, std::string& err)
{
    modelnet::SwarmGeneration gen("subject-a", parent, "coordinator-1");
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
    if (!gen.Train(err) || !gen.Measure(first, err) || !gen.Measure(second, err) || !gen.MeasureAccepted()) {
        err = err.empty() ? std::string("MEASURE") : err;
    }
    return gen;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_graduate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(realm_promotion_does_not_graduate)
{
    std::string err = "prior";
    modelnet::SwarmGeneration gen = Ready("baseline-realm", err);
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(gen.MeasureAccepted());

    modelnet::SwarmEvolveGraduateRequest realm;
    realm.realm_promote = true;
    BOOST_CHECK(!gen.Graduate(realm, err));
    BOOST_CHECK_EQUAL(err, "REALM");
    BOOST_CHECK(!gen.Graduated());
    BOOST_CHECK(gen.GraduatedId().empty());
    BOOST_CHECK(!gen.RealmPromoted());
    BOOST_CHECK(!gen.ExactReplayAdmitted());

    modelnet::SwarmEvolveGraduateRequest safety;
    safety.safety_regression = true;
    modelnet::SwarmGeneration safety_gen = Ready("baseline-safety", err);
    BOOST_REQUIRE(err.empty());
    BOOST_CHECK(!safety_gen.Graduate(safety, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!safety_gen.Graduated());
    BOOST_CHECK(!safety_gen.ExactReplayAdmitted());
    BOOST_CHECK(!safety_gen.RealmPromoted());

    modelnet::SwarmEvolveGraduateRequest broad;
    broad.broad_regression = true;
    modelnet::SwarmGeneration broad_gen = Ready("baseline-broad", err);
    BOOST_REQUIRE(err.empty());
    BOOST_CHECK(!broad_gen.Graduate(broad, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!broad_gen.Graduated());
    BOOST_CHECK(!broad_gen.ExactReplayAdmitted());

    modelnet::SwarmGeneration early("subject-a", "baseline-early", "coordinator-1");
    modelnet::SwarmEvolveGraduateRequest plain;
    BOOST_CHECK(!early.Graduate(plain, err));
    BOOST_CHECK_EQUAL(err, "MEASURE");
    BOOST_CHECK(!early.ExactReplayAdmitted());

    modelnet::SwarmGeneration passed = Ready("baseline-pass", err);
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(passed.Graduate(plain, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(passed.Graduated());
    BOOST_CHECK(!passed.GraduatedId().empty());
    BOOST_CHECK(!passed.RealmPromoted());
    BOOST_CHECK(!passed.ExactReplayAdmitted());
    BOOST_CHECK_EQUAL(passed.AutomaticSpend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
