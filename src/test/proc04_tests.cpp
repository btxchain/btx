// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc04/proc04.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(proc04_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(compare_latches)
{
    modelnet::Proc04 eng;
    std::string err = "stale";
    const std::string spend = eng.automatic_spend();

    BOOST_CHECK(!eng.compared());
    BOOST_CHECK_EQUAL(eng.corpus_count(), 0);
    BOOST_CHECK_EQUAL(eng.single_agent_score(), 0);
    BOOST_CHECK_EQUAL(eng.central_score(), 0);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(spend, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(spend, "0");

    BOOST_CHECK(!eng.RefuseEmpty("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.compared());
    BOOST_CHECK_EQUAL(eng.corpus_count(), 0);
    BOOST_CHECK_EQUAL(eng.single_agent_score(), 0);
    BOOST_CHECK_EQUAL(eng.central_score(), 0);

    err = "stale";
    BOOST_CHECK(eng.RefuseEmpty("delta", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.compared());
    BOOST_CHECK_EQUAL(eng.corpus_count(), 0);

    err = "stale";
    BOOST_CHECK(eng.Compare(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.compared());
    BOOST_CHECK_EQUAL(eng.corpus_count(), 3);
    // lengths 5+4+5; distinct characters alpha 4, beta 4, gamma 3 (a, g, m)
    BOOST_CHECK_EQUAL(eng.single_agent_score(), 14);
    BOOST_CHECK_EQUAL(eng.central_score(), 11);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), spend);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());

    const int single = eng.single_agent_score();
    const int central = eng.central_score();
    err = "stale";
    BOOST_CHECK(eng.Compare(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.compared());
    BOOST_CHECK_EQUAL(eng.corpus_count(), 3);
    BOOST_CHECK_EQUAL(eng.single_agent_score(), single);
    BOOST_CHECK_EQUAL(eng.central_score(), central);

    BOOST_CHECK(!eng.RefuseEmpty("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.compared());
    BOOST_CHECK_EQUAL(eng.corpus_count(), 3);
    BOOST_CHECK_EQUAL(eng.single_agent_score(), 14);
    BOOST_CHECK_EQUAL(eng.central_score(), 11);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_SUITE_END()
