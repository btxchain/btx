// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

bool Prepare(modelnet::SwarmGeneration& gen, std::string& err)
{
    modelnet::SwarmEvolveScoreReport first;
    first.author = "judge-1";
    first.subject = "subject-a";
    first.domain = "coding";
    first.score = 2000;
    first.independent = true;
    first.rotating = true;
    modelnet::SwarmEvolveScoreReport second = first;
    second.author = "judge-2";
    second.domain = "research";
    second.score = 8000;
    modelnet::SwarmEvolveGraduateRequest request;
    return gen.Train(err) && gen.Measure(first, err) && gen.Measure(second, err) && gen.MeasureAccepted() && gen.Graduate(request, err);
}

bool Contains(const std::vector<std::string>& ids, const std::string& want)
{
    for (const std::string& id : ids) {
        if (id == want) return true;
    }
    return false;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_adopt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(adopt_sets_the_parent_and_average_leaves_it)
{
    modelnet::SwarmGeneration gen("subject-a", "baseline-parent", "coordinator-1");
    std::string err = "prior";
    BOOST_CHECK_EQUAL(gen.Parent(), "baseline-parent");
    BOOST_CHECK(!gen.Adopt(err));
    BOOST_CHECK_EQUAL(err, "GRADUATE");
    BOOST_CHECK_EQUAL(gen.Parent(), "baseline-parent");

    const std::string parent_before = gen.Parent();
    BOOST_CHECK(!gen.Average("fork-left", "fork-right", err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK_EQUAL(gen.Parent(), parent_before);

    BOOST_REQUIRE(Prepare(gen, err));
    BOOST_CHECK(err.empty());
    const std::string graduated = gen.GraduatedId();
    BOOST_REQUIRE(!graduated.empty());
    BOOST_REQUIRE(gen.Adopt(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gen.Adopted());
    BOOST_CHECK_EQUAL(gen.Parent(), graduated);
    BOOST_CHECK(Contains(gen.Heads("general"), graduated));
    BOOST_CHECK(Contains(gen.Heads("general"), "baseline-parent"));

    BOOST_CHECK(!gen.Adopt(err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gen.Parent(), graduated);

    BOOST_CHECK(!gen.Average("fork-left", "fork-right", err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK_EQUAL(gen.Parent(), graduated);
    BOOST_CHECK(Contains(gen.Heads("general"), graduated));
    BOOST_CHECK(!gen.ExactReplayAdmitted());
}

BOOST_AUTO_TEST_SUITE_END()
