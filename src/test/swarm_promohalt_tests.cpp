// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promohalt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

modelnet::SwarmPromotionAttempt Attempt(const std::string& candidate_id, bool started, bool interrupted)
{
    modelnet::SwarmPromotionAttempt attempt;
    attempt.candidate_id = candidate_id;
    attempt.started = started;
    attempt.interrupted = interrupted;
    return attempt;
}

void ExpectHalt(const modelnet::SwarmPromotionAttempt& attempt, const char* code, bool err_cleared)
{
    std::string err = "stale";
    const modelnet::SwarmPromotionHalt halt = modelnet::SwarmHaltPromotion(attempt, err);
    BOOST_CHECK(!halt.graduated);
    BOOST_CHECK_EQUAL(halt.code, code);
    if (err_cleared) {
        BOOST_CHECK(err.empty());
    } else {
        BOOST_CHECK_EQUAL(err, code);
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_promohalt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_promotion)
{
    ExpectHalt(Attempt("", false, false), "PROMOTION", false);
    ExpectHalt(Attempt("", true, false), "PROMOTION", false);
    ExpectHalt(Attempt("", false, true), "PROMOTION", false);
    ExpectHalt(Attempt("", true, true), "PROMOTION", false);
}

BOOST_AUTO_TEST_CASE(not_started_even_when_interrupted)
{
    ExpectHalt(Attempt("cand", false, false), "NOT_STARTED", false);
    ExpectHalt(Attempt("cand", false, true), "NOT_STARTED", false);
}

BOOST_AUTO_TEST_CASE(started_and_interrupted)
{
    ExpectHalt(Attempt("cand", true, true), "INTERRUPTED", false);
}

BOOST_AUTO_TEST_CASE(held_does_not_graduate)
{
    ExpectHalt(Attempt("cand", true, false), "HELD", true);
}

BOOST_AUTO_TEST_SUITE_END()
