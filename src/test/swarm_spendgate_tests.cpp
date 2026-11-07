// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_spendgate.h>
#include <test/util/setup_common.h>

#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_spendgate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_scheduler_id_is_spend)
{
    std::string err = "prior";
    modelnet::SwarmSpendRequest request;
    request.scheduler_id = "";
    request.atoms = 100;
    request.spend_key_present = false;
    const modelnet::SwarmSpendResult empty = modelnet::SwarmRefuseSchedulerSpend(request, err);
    BOOST_CHECK(!empty.signed_spend);
    BOOST_CHECK_EQUAL(empty.code, "SPEND");
    BOOST_CHECK_EQUAL(err, "SPEND");

    request.spend_key_present = true;
    const modelnet::SwarmSpendResult empty_with_key = modelnet::SwarmRefuseSchedulerSpend(request, err);
    BOOST_CHECK(!empty_with_key.signed_spend);
    BOOST_CHECK_EQUAL(empty_with_key.code, "SPEND");
    BOOST_CHECK_EQUAL(err, "SPEND");
}

BOOST_AUTO_TEST_CASE(non_positive_atoms_are_spend)
{
    std::string err = "prior";
    modelnet::SwarmSpendRequest request;
    request.scheduler_id = "sched-1";
    request.atoms = 0;
    request.spend_key_present = true;
    const modelnet::SwarmSpendResult zero = modelnet::SwarmRefuseSchedulerSpend(request, err);
    BOOST_CHECK(!zero.signed_spend);
    BOOST_CHECK_EQUAL(zero.code, "SPEND");
    BOOST_CHECK_EQUAL(err, "SPEND");

    request.atoms = -1;
    request.spend_key_present = false;
    const modelnet::SwarmSpendResult negative = modelnet::SwarmRefuseSchedulerSpend(request, err);
    BOOST_CHECK(!negative.signed_spend);
    BOOST_CHECK_EQUAL(negative.code, "SPEND");
    BOOST_CHECK_EQUAL(err, "SPEND");
}

BOOST_AUTO_TEST_CASE(spend_key_present_is_key_refused)
{
    std::string err = "prior";
    modelnet::SwarmSpendRequest request;
    request.scheduler_id = "sched-1";
    request.atoms = 100;
    request.spend_key_present = true;
    const modelnet::SwarmSpendResult result = modelnet::SwarmRefuseSchedulerSpend(request, err);
    BOOST_CHECK(!result.signed_spend);
    BOOST_CHECK_EQUAL(result.code, "KEY_REFUSED");
    BOOST_CHECK_EQUAL(err, "KEY_REFUSED");
}

BOOST_AUTO_TEST_CASE(otherwise_refused_and_unsigned)
{
    std::string err = "prior";
    modelnet::SwarmSpendRequest request;
    request.scheduler_id = "sched-1";
    request.atoms = 1;
    request.spend_key_present = false;
    const modelnet::SwarmSpendResult edge = modelnet::SwarmRefuseSchedulerSpend(request, err);
    BOOST_CHECK(!edge.signed_spend);
    BOOST_CHECK_EQUAL(edge.code, "REFUSED");
    BOOST_CHECK(err.empty());

    err = "prior";
    request.atoms = 250;
    const modelnet::SwarmSpendResult larger = modelnet::SwarmRefuseSchedulerSpend(request, err);
    BOOST_CHECK(!larger.signed_spend);
    BOOST_CHECK_EQUAL(larger.code, "REFUSED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
