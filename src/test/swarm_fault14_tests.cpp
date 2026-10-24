// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault14.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault14_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmFault14 in;
    in.mature = true;
    in.disrupted = true;
    in.refund_signed = true;
    in.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmFault14Result result = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(unsigned_even_if_want_broadcast_or_mature)
{
    modelnet::SwarmFault14 in;
    in.channel_id = "channel-1";
    in.refund_signed = false;
    in.want_broadcast = true;
    in.mature = true;
    in.disrupted = true;
    std::string err = "prior";
    const modelnet::SwarmFault14Result broadcast = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(broadcast.code, "UNSIGNED");
    BOOST_CHECK(!broadcast.refunded);
    BOOST_CHECK(!broadcast.broadcast);
    BOOST_CHECK(!broadcast.committed);
    BOOST_CHECK_EQUAL(err, "UNSIGNED");

    in.want_broadcast = false;
    in.disrupted = false;
    in.mature = true;
    const modelnet::SwarmFault14Result mature = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(mature.code, "UNSIGNED");
    BOOST_CHECK(!mature.refunded);
    BOOST_CHECK(!mature.broadcast);
    BOOST_CHECK(!mature.committed);
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_held)
{
    modelnet::SwarmFault14 in;
    in.channel_id = "channel-1";
    in.refund_signed = true;
    in.want_broadcast = true;
    in.mature = true;
    in.disrupted = true;
    std::string err = "prior";
    const modelnet::SwarmFault14Result result = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(disrupted_or_mature_is_not_live)
{
    modelnet::SwarmFault14 in;
    in.channel_id = "channel-1";
    in.refund_signed = true;
    in.want_broadcast = false;
    in.disrupted = true;
    in.mature = false;
    std::string err = "prior";
    const modelnet::SwarmFault14Result disrupted = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(disrupted.code, "NOT_LIVE");
    BOOST_CHECK(!disrupted.refunded);
    BOOST_CHECK(!disrupted.broadcast);
    BOOST_CHECK(!disrupted.committed);
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");

    in.disrupted = false;
    in.mature = true;
    const modelnet::SwarmFault14Result mature = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(mature.code, "NOT_LIVE");
    BOOST_CHECK(!mature.refunded);
    BOOST_CHECK(!mature.broadcast);
    BOOST_CHECK(!mature.committed);
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");

    in.disrupted = true;
    in.mature = true;
    const modelnet::SwarmFault14Result both = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(both.code, "NOT_LIVE");
    BOOST_CHECK(!both.refunded);
    BOOST_CHECK(!both.broadcast);
    BOOST_CHECK(!both.committed);
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    modelnet::SwarmFault14 in;
    in.channel_id = "channel-1";
    in.refund_signed = true;
    in.want_broadcast = false;
    in.disrupted = false;
    in.mature = false;
    std::string err = "prior";
    const modelnet::SwarmFault14Result result = modelnet::SwarmRecoverFault14(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
