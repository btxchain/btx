// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundhold.h>
#include <test/util/setup_common.h>

#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_refundhold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(negative_height_or_refund_height_is_refund)
{
    std::string err = "prior";
    modelnet::SwarmRefundHoldRequest request;
    request.height = -1;
    request.refund_height = 10;
    request.want_broadcast = true;
    request.disrupted = true;
    const modelnet::SwarmRefundHoldResult negative = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(!negative.mature);
    BOOST_CHECK(!negative.broadcast);
    BOOST_CHECK_EQUAL(negative.code, "REFUND");
    BOOST_CHECK_EQUAL(err, "REFUND");

    request.height = 10;
    request.refund_height = 0;
    const modelnet::SwarmRefundHoldResult zero = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(!zero.mature);
    BOOST_CHECK(!zero.broadcast);
    BOOST_CHECK_EQUAL(zero.code, "REFUND");
    BOOST_CHECK_EQUAL(err, "REFUND");

    request.refund_height = -3;
    const modelnet::SwarmRefundHoldResult below = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(!below.mature);
    BOOST_CHECK(!below.broadcast);
    BOOST_CHECK_EQUAL(below.code, "REFUND");
    BOOST_CHECK_EQUAL(err, "REFUND");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_forbidden_even_when_mature_and_disrupted)
{
    std::string err = "prior";
    modelnet::SwarmRefundHoldRequest request;
    request.height = 12;
    request.refund_height = 10;
    request.disrupted = true;
    request.want_broadcast = true;
    const modelnet::SwarmRefundHoldResult mature = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(!mature.mature);
    BOOST_CHECK(!mature.broadcast);
    BOOST_CHECK_EQUAL(mature.code, "BROADCAST_FORBIDDEN");
    BOOST_CHECK_EQUAL(err, "BROADCAST_FORBIDDEN");

    request.height = 4;
    request.disrupted = false;
    const modelnet::SwarmRefundHoldResult early = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(!early.mature);
    BOOST_CHECK(!early.broadcast);
    BOOST_CHECK_EQUAL(early.code, "BROADCAST_FORBIDDEN");
    BOOST_CHECK_EQUAL(err, "BROADCAST_FORBIDDEN");
}

BOOST_AUTO_TEST_CASE(height_before_refund_is_early)
{
    std::string err = "prior";
    modelnet::SwarmRefundHoldRequest request;
    request.height = 4;
    request.refund_height = 10;
    request.disrupted = true;
    const modelnet::SwarmRefundHoldResult result = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(!result.mature);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "EARLY");
    BOOST_CHECK_EQUAL(err, "EARLY");
}

BOOST_AUTO_TEST_CASE(disrupted_at_refund_height_is_held)
{
    std::string err = "prior";
    modelnet::SwarmRefundHoldRequest request;
    request.height = 10;
    request.refund_height = 10;
    request.disrupted = true;
    const modelnet::SwarmRefundHoldResult result = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(result.mature);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "DISRUPTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(reached_refund_height_is_mature_without_broadcast)
{
    std::string err = "prior";
    modelnet::SwarmRefundHoldRequest request;
    request.height = 10;
    request.refund_height = 10;
    const modelnet::SwarmRefundHoldResult at = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(at.mature);
    BOOST_CHECK(!at.broadcast);
    BOOST_CHECK_EQUAL(at.code, "MATURE");
    BOOST_CHECK(err.empty());

    request.height = 15;
    const modelnet::SwarmRefundHoldResult past = modelnet::SwarmHoldRefund(request, err);
    BOOST_CHECK(past.mature);
    BOOST_CHECK(!past.broadcast);
    BOOST_CHECK_EQUAL(past.code, "MATURE");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
