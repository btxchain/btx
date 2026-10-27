// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fallback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fallback_tests, BasicTestingSetup)

static modelnet::SwarmFallback NotedFallback()
{
    modelnet::SwarmFallback fallback;
    fallback.peer_id = "peer-a";
    fallback.authorized = true;
    fallback.inside_chosen = false;
    fallback.rtt_ms = 10;
    fallback.want_connect = false;
    return fallback;
}

static void ExpectClosed(const modelnet::SwarmFallbackResult& result)
{
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.socket_opened);
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_fallback)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.peer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "FALLBACK");
    BOOST_CHECK_EQUAL(err, "FALLBACK");
}

BOOST_AUTO_TEST_CASE(negative_rtt_is_fallback)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.rtt_ms = -1;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "FALLBACK");
    BOOST_CHECK_EQUAL(err, "FALLBACK");
}

BOOST_AUTO_TEST_CASE(fallback_wins_over_want_connect)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.peer_id.clear();
    fallback.authorized = false;
    fallback.inside_chosen = true;
    fallback.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "FALLBACK");
    BOOST_CHECK_EQUAL(err, "FALLBACK");
}

BOOST_AUTO_TEST_CASE(unauthorized_is_unauthorized)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.authorized = false;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
}

BOOST_AUTO_TEST_CASE(unauthorized_wins_over_want_connect)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.authorized = false;
    fallback.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
}

BOOST_AUTO_TEST_CASE(unauthorized_wins_over_inside_chosen)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.authorized = false;
    fallback.inside_chosen = true;
    fallback.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
}

BOOST_AUTO_TEST_CASE(inside_chosen_is_not_fallback)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.inside_chosen = true;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_FALLBACK");
    BOOST_CHECK_EQUAL(err, "NOT_FALLBACK");
}

BOOST_AUTO_TEST_CASE(not_fallback_wins_over_want_connect)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.inside_chosen = true;
    fallback.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_FALLBACK");
    BOOST_CHECK_EQUAL(err, "NOT_FALLBACK");
}

BOOST_AUTO_TEST_CASE(want_connect_is_held)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(authorized_outside_chosen_is_noted)
{
    modelnet::SwarmFallback fallback = NotedFallback();
    fallback.authorized = true;
    fallback.inside_chosen = false;
    fallback.rtt_ms = 10;
    fallback.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmFallbackResult result = modelnet::SwarmNoteFallback(fallback, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
