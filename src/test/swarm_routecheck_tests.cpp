// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routecheck.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_routecheck_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hops_below_one_is_route)
{
    std::string err = "prior";
    modelnet::SwarmRouteRequest request;
    request.hops = 0;
    request.preimage_len = 32;
    request.cltv_staggered = true;
    request.lifetime_ok = true;
    request.liquidity_reserved = true;
    const modelnet::SwarmRouteResult zero = modelnet::SwarmCheckRoute(request, err);
    BOOST_CHECK(!zero.qualified);
    BOOST_CHECK(!zero.secp_penalty);
    BOOST_CHECK_EQUAL(zero.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");

    request.hops = -1;
    request.preimage_len = 0;
    std::string err_negative = "prior";
    const modelnet::SwarmRouteResult negative = modelnet::SwarmCheckRoute(request, err_negative);
    BOOST_CHECK(!negative.qualified);
    BOOST_CHECK(!negative.secp_penalty);
    BOOST_CHECK_EQUAL(negative.code, "ROUTE");
    BOOST_CHECK_EQUAL(err_negative, "ROUTE");
}

BOOST_AUTO_TEST_CASE(preimage_not_32_is_preimage)
{
    std::string err = "prior";
    modelnet::SwarmRouteRequest request;
    request.hops = 2;
    request.preimage_len = 31;
    request.cltv_staggered = false;
    request.lifetime_ok = false;
    request.liquidity_reserved = false;
    const modelnet::SwarmRouteResult short_preimage = modelnet::SwarmCheckRoute(request, err);
    BOOST_CHECK(!short_preimage.qualified);
    BOOST_CHECK(!short_preimage.secp_penalty);
    BOOST_CHECK_EQUAL(short_preimage.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");

    request.hops = 1;
    request.preimage_len = 33;
    request.cltv_staggered = true;
    request.lifetime_ok = true;
    request.liquidity_reserved = true;
    std::string err_long = "prior";
    const modelnet::SwarmRouteResult long_preimage = modelnet::SwarmCheckRoute(request, err_long);
    BOOST_CHECK(!long_preimage.qualified);
    BOOST_CHECK(!long_preimage.secp_penalty);
    BOOST_CHECK_EQUAL(long_preimage.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err_long, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(one_hop_hashlock_is_direct)
{
    std::string err = "prior";
    modelnet::SwarmRouteRequest request;
    request.hops = 1;
    request.preimage_len = 32;
    request.cltv_staggered = false;
    request.lifetime_ok = true;
    request.liquidity_reserved = true;
    const modelnet::SwarmRouteResult result = modelnet::SwarmCheckRoute(request, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "DIRECT");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(missing_stagger_is_stagger)
{
    std::string err = "prior";
    modelnet::SwarmRouteRequest request;
    request.hops = 2;
    request.preimage_len = 32;
    request.cltv_staggered = false;
    request.lifetime_ok = true;
    request.liquidity_reserved = true;
    const modelnet::SwarmRouteResult result = modelnet::SwarmCheckRoute(request, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "STAGGER");
    BOOST_CHECK_EQUAL(err, "STAGGER");
}

BOOST_AUTO_TEST_CASE(missing_lifetime_is_lifetime)
{
    std::string err = "prior";
    modelnet::SwarmRouteRequest request;
    request.hops = 3;
    request.preimage_len = 32;
    request.cltv_staggered = true;
    request.lifetime_ok = false;
    request.liquidity_reserved = true;
    const modelnet::SwarmRouteResult multi = modelnet::SwarmCheckRoute(request, err);
    BOOST_CHECK(!multi.qualified);
    BOOST_CHECK(!multi.secp_penalty);
    BOOST_CHECK_EQUAL(multi.code, "LIFETIME");
    BOOST_CHECK_EQUAL(err, "LIFETIME");

    request.hops = 1;
    request.liquidity_reserved = false;
    std::string err_direct = "prior";
    const modelnet::SwarmRouteResult direct = modelnet::SwarmCheckRoute(request, err_direct);
    BOOST_CHECK(!direct.qualified);
    BOOST_CHECK(!direct.secp_penalty);
    BOOST_CHECK_EQUAL(direct.code, "LIFETIME");
    BOOST_CHECK_EQUAL(err_direct, "LIFETIME");
}

BOOST_AUTO_TEST_CASE(missing_liquidity_is_liquidity)
{
    std::string err = "prior";
    modelnet::SwarmRouteRequest request;
    request.hops = 2;
    request.preimage_len = 32;
    request.cltv_staggered = true;
    request.lifetime_ok = true;
    request.liquidity_reserved = false;
    const modelnet::SwarmRouteResult multi = modelnet::SwarmCheckRoute(request, err);
    BOOST_CHECK(!multi.qualified);
    BOOST_CHECK(!multi.secp_penalty);
    BOOST_CHECK_EQUAL(multi.code, "LIQUIDITY");
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");

    request.hops = 1;
    std::string err_direct = "prior";
    const modelnet::SwarmRouteResult direct = modelnet::SwarmCheckRoute(request, err_direct);
    BOOST_CHECK(!direct.qualified);
    BOOST_CHECK(!direct.secp_penalty);
    BOOST_CHECK_EQUAL(direct.code, "LIQUIDITY");
    BOOST_CHECK_EQUAL(err_direct, "LIQUIDITY");
}

BOOST_AUTO_TEST_CASE(complete_multihop_is_unqualified)
{
    std::string err = "prior";
    modelnet::SwarmRouteRequest request;
    request.hops = 4;
    request.preimage_len = 32;
    request.cltv_staggered = true;
    request.lifetime_ok = true;
    request.liquidity_reserved = true;
    const modelnet::SwarmRouteResult result = modelnet::SwarmCheckRoute(request, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
