// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_opportunity.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_opportunity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_activity_is_opportunity)
{
    std::string err;
    modelnet::SwarmOpportunityRequest request;
    request.activity = "";
    request.advertised_pool_atoms = 1000000;
    request.pool_funded = true;
    request.payment_enforceable = true;
    request.meter_measured = true;
    request.compensation_atoms = 50;
    const modelnet::SwarmOpportunityResult result = modelnet::SwarmCompareOpportunity(request, err);
    BOOST_CHECK(!result.comparable);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.compensation_atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "OPPORTUNITY");
    BOOST_CHECK_EQUAL(err, "OPPORTUNITY");
}

BOOST_AUTO_TEST_CASE(unknown_activity_is_opportunity)
{
    std::string err;
    modelnet::SwarmOpportunityRequest request;
    request.activity = "trade";
    request.advertised_pool_atoms = 1000000;
    request.pool_funded = true;
    request.payment_enforceable = true;
    request.meter_measured = true;
    request.compensation_atoms = 50;
    const modelnet::SwarmOpportunityResult result = modelnet::SwarmCompareOpportunity(request, err);
    BOOST_CHECK(!result.comparable);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.compensation_atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "OPPORTUNITY");
    BOOST_CHECK_EQUAL(err, "OPPORTUNITY");
}

BOOST_AUTO_TEST_CASE(nonpositive_compensation_is_opportunity)
{
    std::string err;
    modelnet::SwarmOpportunityRequest request;
    request.activity = "mine";
    request.advertised_pool_atoms = 1000000;
    request.pool_funded = true;
    request.payment_enforceable = true;
    request.meter_measured = true;
    request.compensation_atoms = 0;
    const modelnet::SwarmOpportunityResult result = modelnet::SwarmCompareOpportunity(request, err);
    BOOST_CHECK(!result.comparable);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.compensation_atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "OPPORTUNITY");
    BOOST_CHECK_EQUAL(err, "OPPORTUNITY");

    request.compensation_atoms = -1;
    std::string err_negative;
    const modelnet::SwarmOpportunityResult negative = modelnet::SwarmCompareOpportunity(request, err_negative);
    BOOST_CHECK(!negative.comparable);
    BOOST_CHECK(!negative.spendable);
    BOOST_CHECK_EQUAL(negative.compensation_atoms, 0);
    BOOST_CHECK_EQUAL(negative.code, "OPPORTUNITY");
    BOOST_CHECK_EQUAL(err_negative, "OPPORTUNITY");
}

BOOST_AUTO_TEST_CASE(unfunded_advertised_pool_stays_zero)
{
    std::string err;
    modelnet::SwarmOpportunityRequest request;
    request.activity = "inference";
    request.advertised_pool_atoms = 1000000;
    request.pool_funded = false;
    request.payment_enforceable = true;
    request.meter_measured = true;
    request.compensation_atoms = 500;
    const modelnet::SwarmOpportunityResult result = modelnet::SwarmCompareOpportunity(request, err);
    BOOST_CHECK(!result.comparable);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.compensation_atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "UNFUNDED");
    BOOST_CHECK_EQUAL(err, "UNFUNDED");
}

BOOST_AUTO_TEST_CASE(unenforceable_payment_is_unenforceable)
{
    std::string err;
    modelnet::SwarmOpportunityRequest request;
    request.activity = "rollout";
    request.advertised_pool_atoms = 1000000;
    request.pool_funded = true;
    request.payment_enforceable = false;
    request.meter_measured = true;
    request.compensation_atoms = 500;
    const modelnet::SwarmOpportunityResult result = modelnet::SwarmCompareOpportunity(request, err);
    BOOST_CHECK(!result.comparable);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.compensation_atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "UNENFORCEABLE");
    BOOST_CHECK_EQUAL(err, "UNENFORCEABLE");
}

BOOST_AUTO_TEST_CASE(absent_meter_is_meter_absent)
{
    std::string err;
    modelnet::SwarmOpportunityRequest request;
    request.activity = "train";
    request.advertised_pool_atoms = 1000000;
    request.pool_funded = true;
    request.payment_enforceable = true;
    request.meter_measured = false;
    request.compensation_atoms = 500;
    const modelnet::SwarmOpportunityResult result = modelnet::SwarmCompareOpportunity(request, err);
    BOOST_CHECK(!result.comparable);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.compensation_atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "METER_ABSENT");
    BOOST_CHECK_EQUAL(err, "METER_ABSENT");
}

BOOST_AUTO_TEST_CASE(known_activity_is_comparable_and_not_spendable)
{
    const char* activities[] = {
        "mine",
        "inference",
        "rollout",
        "train",
        "evaluate",
        "challenge",
        "simulate",
        "serve",
        "reproduce",
    };
    for (const char* activity : activities) {
        std::string err = "prior";
        modelnet::SwarmOpportunityRequest request;
        request.activity = activity;
        request.advertised_pool_atoms = 1000000;
        request.pool_funded = true;
        request.payment_enforceable = true;
        request.meter_measured = true;
        request.compensation_atoms = 2500;
        const modelnet::SwarmOpportunityResult result = modelnet::SwarmCompareOpportunity(request, err);
        BOOST_CHECK(result.comparable);
        BOOST_CHECK(!result.spendable);
        BOOST_CHECK_EQUAL(result.compensation_atoms, 2500);
        BOOST_CHECK_EQUAL(result.code, "COMPARABLE");
        BOOST_CHECK(err.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
