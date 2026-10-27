// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closerefund.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_closerefund_tests, BasicTestingSetup)

static modelnet::SwarmCloseRefund NotedClose()
{
    modelnet::SwarmCloseRefund close;
    close.channel_id = "ch";
    close.margin = 160;
    close.want_shrink = false;
    close.want_broadcast = false;
    return close;
}

BOOST_AUTO_TEST_CASE(empty_channel_is_channel)
{
    modelnet::SwarmCloseRefund close = NotedClose();
    close.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmCloseRefundResult result = modelnet::SwarmRecordClose(close, err);
    BOOST_CHECK_EQUAL(result.shrunk, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 160);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(margin_100_is_margin)
{
    modelnet::SwarmCloseRefund close = NotedClose();
    close.margin = 100;
    std::string err = "prior";
    const modelnet::SwarmCloseRefundResult result = modelnet::SwarmRecordClose(close, err);
    BOOST_CHECK_EQUAL(result.shrunk, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 160);
    BOOST_CHECK_EQUAL(result.code, "MARGIN");
    BOOST_CHECK_EQUAL(err, "MARGIN");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_held)
{
    modelnet::SwarmCloseRefund close = NotedClose();
    close.margin = 160;
    close.want_shrink = false;
    close.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmCloseRefundResult result = modelnet::SwarmRecordClose(close, err);
    BOOST_CHECK_EQUAL(result.shrunk, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 160);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(margin_160_is_noted)
{
    modelnet::SwarmCloseRefund close = NotedClose();
    close.margin = 160;
    close.want_shrink = false;
    close.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmCloseRefundResult result = modelnet::SwarmRecordClose(close, err);
    BOOST_CHECK_EQUAL(result.shrunk, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.blocks, 160);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
