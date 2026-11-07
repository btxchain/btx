// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

modelnet::SwarmEvolveScoreReport Report(const std::string& author, const std::string& domain, int64_t score, bool independent, bool rotating)
{
    modelnet::SwarmEvolveScoreReport report;
    report.author = author;
    report.subject = "subject-a";
    report.domain = domain;
    report.score = score;
    report.independent = independent;
    report.rotating = rotating;
    return report;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_measure_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(measure_refuses_until_two_distinct_reports_agree)
{
    modelnet::SwarmGeneration gen("subject-a", "baseline-parent", "coordinator-1");
    std::string err = "prior";
    BOOST_CHECK(!gen.Measure(Report("judge-1", "coding", 1000, true, true), err));
    BOOST_CHECK_EQUAL(err, "TRAIN");
    BOOST_CHECK(!gen.MeasureAccepted());
    BOOST_CHECK(gen.Scores().empty());

    BOOST_REQUIRE(gen.Train(err));
    BOOST_CHECK(!gen.Measure(Report("subject-a", "coding", 1000, true, true), err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_CHECK(gen.Scores().empty());

    BOOST_CHECK(!gen.Measure(Report("judge-1", "coding", 1000, false, true), err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(gen.Scores().empty());

    BOOST_CHECK(!gen.Measure(Report("judge-1", "coding", 1000, true, false), err));
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
    BOOST_CHECK(gen.Scores().empty());

    BOOST_REQUIRE(gen.Measure(Report("judge-1", "coding", 1000, true, true), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!gen.MeasureAccepted());
    BOOST_REQUIRE(gen.Measure(Report("judge-1", "research", 1000, true, true), err));
    BOOST_CHECK(!gen.MeasureAccepted());

    modelnet::SwarmGeneration spread("subject-a", "baseline-spread", "coordinator-1");
    BOOST_REQUIRE(spread.Train(err));
    BOOST_REQUIRE(spread.Measure(Report("judge-1", "coding", 0, true, true), err));
    BOOST_REQUIRE(spread.Measure(Report("judge-2", "research", 10001, true, true), err));
    BOOST_CHECK(!spread.MeasureAccepted());
    BOOST_REQUIRE_EQUAL(spread.Scores().size(), 2U);
    BOOST_CHECK_EQUAL(spread.Scores()[0], 0);
    BOOST_CHECK_EQUAL(spread.Scores()[1], 10001);

    modelnet::SwarmGeneration same_domain("subject-a", "baseline-domain", "coordinator-1");
    BOOST_REQUIRE(same_domain.Train(err));
    BOOST_REQUIRE(same_domain.Measure(Report("judge-1", "coding", 1000, true, true), err));
    BOOST_REQUIRE(same_domain.Measure(Report("judge-2", "coding", 2000, true, true), err));
    BOOST_CHECK(!same_domain.MeasureAccepted());

    BOOST_REQUIRE(gen.Measure(Report("judge-2", "research", 11000, true, true), err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(gen.MeasureAccepted());
    BOOST_REQUIRE_EQUAL(gen.Scores().size(), 3U);
    BOOST_CHECK_EQUAL(gen.Scores()[0], 1000);
    BOOST_CHECK_EQUAL(gen.Scores()[1], 1000);
    BOOST_CHECK_EQUAL(gen.Scores()[2], 11000);
}

BOOST_AUTO_TEST_CASE(an_accepting_pair_keeps_both_scores)
{
    modelnet::SwarmGeneration gen("subject-a", "baseline-pair", "coordinator-1");
    std::string err = "prior";
    BOOST_REQUIRE(gen.Train(err));
    BOOST_REQUIRE(gen.Measure(Report("judge-1", "coding", 1000, true, true), err));
    BOOST_REQUIRE(gen.Measure(Report("judge-2", "research", 11000, true, true), err));
    BOOST_REQUIRE(gen.MeasureAccepted());
    BOOST_REQUIRE_EQUAL(gen.Scores().size(), 2U);
    BOOST_CHECK_EQUAL(gen.Scores()[0], 1000);
    BOOST_CHECK_EQUAL(gen.Scores()[1], 11000);
}

BOOST_AUTO_TEST_SUITE_END()
