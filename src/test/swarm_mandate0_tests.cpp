// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mandate0.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_mandate0_tests, BasicTestingSetup)

static modelnet::SwarmMandateSpend HeldSpend()
{
    modelnet::SwarmMandateSpend spend;
    spend.mandate_id = "mandate-1";
    spend.operator_signed = true;
    spend.bound_atoms = 100;
    spend.requested_atoms = 50;
    return spend;
}

BOOST_AUTO_TEST_CASE(empty_mandate_id_is_mandate)
{
    modelnet::SwarmMandateSpend spend = HeldSpend();
    spend.mandate_id.clear();
    std::string err = "prior";
    const modelnet::SwarmMandateSpendResult result = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(result.automatic_spend, 0);
    BOOST_CHECK_EQUAL(result.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");

    spend.operator_signed = false;
    spend.requested_atoms = spend.bound_atoms + 1;
    err = "prior";
    const modelnet::SwarmMandateSpendResult later_rules = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(later_rules.automatic_spend, 0);
    BOOST_CHECK_EQUAL(later_rules.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");
}

BOOST_AUTO_TEST_CASE(bound_below_one_is_mandate)
{
    modelnet::SwarmMandateSpend spend = HeldSpend();
    spend.bound_atoms = 0;
    spend.operator_signed = false;
    std::string err = "prior";
    const modelnet::SwarmMandateSpendResult zero = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(zero.automatic_spend, 0);
    BOOST_CHECK_EQUAL(zero.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");

    spend.bound_atoms = -1;
    spend.operator_signed = true;
    err = "prior";
    const modelnet::SwarmMandateSpendResult negative = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(negative.automatic_spend, 0);
    BOOST_CHECK_EQUAL(negative.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");
}

BOOST_AUTO_TEST_CASE(nonpositive_request_is_mandate)
{
    modelnet::SwarmMandateSpend spend = HeldSpend();
    spend.requested_atoms = 0;
    std::string err = "prior";
    const modelnet::SwarmMandateSpendResult zero = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(zero.automatic_spend, 0);
    BOOST_CHECK_EQUAL(zero.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");

    spend.requested_atoms = -1;
    spend.operator_signed = false;
    err = "prior";
    const modelnet::SwarmMandateSpendResult negative = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(negative.automatic_spend, 0);
    BOOST_CHECK_EQUAL(negative.code, "MANDATE");
    BOOST_CHECK_EQUAL(err, "MANDATE");
}

BOOST_AUTO_TEST_CASE(unsigned_is_unsigned)
{
    modelnet::SwarmMandateSpend spend = HeldSpend();
    spend.operator_signed = false;
    std::string err = "prior";
    const modelnet::SwarmMandateSpendResult result = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(result.automatic_spend, 0);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");

    spend.requested_atoms = spend.bound_atoms + 1;
    err = "prior";
    const modelnet::SwarmMandateSpendResult over_bound = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(over_bound.automatic_spend, 0);
    BOOST_CHECK_EQUAL(over_bound.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(request_above_bound_is_bound)
{
    modelnet::SwarmMandateSpend spend = HeldSpend();
    spend.requested_atoms = spend.bound_atoms + 1;
    std::string err = "prior";
    const modelnet::SwarmMandateSpendResult result = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(result.automatic_spend, 0);
    BOOST_CHECK_EQUAL(result.code, "BOUND");
    BOOST_CHECK_EQUAL(err, "BOUND");
}

BOOST_AUTO_TEST_CASE(signed_within_bound_is_held)
{
    modelnet::SwarmMandateSpend spend = HeldSpend();
    std::string err = "prior";
    const modelnet::SwarmMandateSpendResult under = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(under.automatic_spend, 0);
    BOOST_CHECK_EQUAL(under.code, "HELD");
    BOOST_CHECK(err.empty());

    spend.requested_atoms = spend.bound_atoms;
    err = "prior";
    const modelnet::SwarmMandateSpendResult equal = modelnet::SwarmNoteMandateSpend(spend, err);
    BOOST_CHECK_EQUAL(equal.automatic_spend, 0);
    BOOST_CHECK_EQUAL(equal.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
