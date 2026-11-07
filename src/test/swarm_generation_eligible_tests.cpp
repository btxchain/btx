// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_generation_eligible_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(eligibility_starts_false_and_needs_both_grants)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(!gen.eligible());

    BOOST_CHECK(!gen.Eligible(false, false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK(!gen.eligible());

    // A license alone, including a download allowance, is not a training grant.
    BOOST_CHECK(!gen.Eligible(true, false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK(!gen.eligible());

    BOOST_CHECK(!gen.Eligible(false, true, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK(!gen.eligible());
}

BOOST_AUTO_TEST_CASE(both_grants_mark_the_family_eligible)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(gen.Eligible(true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gen.eligible());

    BOOST_CHECK(!gen.Eligible(true, false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK(gen.eligible());
}

BOOST_AUTO_TEST_SUITE_END()
