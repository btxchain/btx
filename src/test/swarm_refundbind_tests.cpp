// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundbind.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_refundbind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmRefundBind bind;
    bind.channel_id.clear();
    bind.signer = true;
    bind.want_bind = false;
    bind.want_broadcast = false;
    const modelnet::SwarmRefundBindResult result = modelnet::SwarmBindRefundLocal(bind, err);
    BOOST_CHECK(!result.bound);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(signer_false_is_signer)
{
    std::string err = "prior";
    modelnet::SwarmRefundBind bind;
    bind.channel_id = "channel-1";
    bind.signer = false;
    bind.want_bind = false;
    bind.want_broadcast = false;
    const modelnet::SwarmRefundBindResult result = modelnet::SwarmBindRefundLocal(bind, err);
    BOOST_CHECK(!result.bound);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SIGNER");
    BOOST_CHECK_EQUAL(err, "SIGNER");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_held)
{
    std::string err = "prior";
    modelnet::SwarmRefundBind bind;
    bind.channel_id = "channel-1";
    bind.signer = true;
    bind.want_bind = false;
    bind.want_broadcast = true;
    const modelnet::SwarmRefundBindResult result = modelnet::SwarmBindRefundLocal(bind, err);
    BOOST_CHECK(!result.bound);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_bind_is_held)
{
    std::string err = "prior";
    modelnet::SwarmRefundBind bind;
    bind.channel_id = "channel-1";
    bind.signer = true;
    bind.want_bind = true;
    bind.want_broadcast = false;
    const modelnet::SwarmRefundBindResult result = modelnet::SwarmBindRefundLocal(bind, err);
    BOOST_CHECK(!result.bound);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(flags_false_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmRefundBind bind;
    bind.channel_id = "channel-1";
    bind.signer = true;
    bind.want_bind = false;
    bind.want_broadcast = false;
    const modelnet::SwarmRefundBindResult result = modelnet::SwarmBindRefundLocal(bind, err);
    BOOST_CHECK(!result.bound);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
