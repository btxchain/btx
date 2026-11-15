// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_community.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_community_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmCommunity community;
    community.other_active = 1;
    std::string err = "stale";
    const modelnet::SwarmCommunityResult result = modelnet::SwarmNoteCommunity(community, err);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK(!result.continues);
    BOOST_CHECK(!result.stopped);
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(negative_other_active_is_pool)
{
    modelnet::SwarmCommunity community;
    community.pool_id = "pool-a";
    community.other_active = -1;
    community.want_stop = true;
    std::string err = "stale";
    const modelnet::SwarmCommunityResult result = modelnet::SwarmNoteCommunity(community, err);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK(!result.continues);
    BOOST_CHECK(!result.stopped);
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(want_stop_with_others_is_held)
{
    modelnet::SwarmCommunity community;
    community.pool_id = "pool-a";
    community.other_active = 2;
    community.want_stop = true;
    std::string err = "stale";
    const modelnet::SwarmCommunityResult result = modelnet::SwarmNoteCommunity(community, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(result.continues);
    BOOST_CHECK(!result.stopped);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_stop_with_zero_others_is_held)
{
    modelnet::SwarmCommunity community;
    community.pool_id = "pool-a";
    community.other_active = 0;
    community.want_stop = true;
    std::string err = "stale";
    const modelnet::SwarmCommunityResult result = modelnet::SwarmNoteCommunity(community, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.continues);
    BOOST_CHECK(!result.stopped);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(zero_other_active_is_alone)
{
    modelnet::SwarmCommunity community;
    community.pool_id = "pool-a";
    community.other_active = 0;
    std::string err = "stale";
    const modelnet::SwarmCommunityResult result = modelnet::SwarmNoteCommunity(community, err);
    BOOST_CHECK_EQUAL(result.code, "ALONE");
    BOOST_CHECK(!result.continues);
    BOOST_CHECK(!result.stopped);
    BOOST_CHECK_EQUAL(err, "ALONE");
}

BOOST_AUTO_TEST_CASE(active_others_are_noted)
{
    modelnet::SwarmCommunity community;
    community.pool_id = "pool-a";
    community.other_active = 1;
    std::string err = "stale";
    const modelnet::SwarmCommunityResult result = modelnet::SwarmNoteCommunity(community, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(result.continues);
    BOOST_CHECK(!result.stopped);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
