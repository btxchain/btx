// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachestand.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cachestand_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cache)
{
    modelnet::SwarmCacheStand cache;
    cache.cache_id.clear();
    cache.alone = true;
    cache.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmCacheStandResult result = modelnet::SwarmNoteCacheAlone(cache, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(alone_true_want_share_false)
{
    modelnet::SwarmCacheStand cache;
    cache.cache_id = "cache-1";
    cache.alone = true;
    cache.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmCacheStandResult result = modelnet::SwarmNoteCacheAlone(cache, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ALONE");
    BOOST_CHECK_EQUAL(err, "ALONE");
}

BOOST_AUTO_TEST_CASE(want_share_true_alone_false)
{
    modelnet::SwarmCacheStand cache;
    cache.cache_id = "cache-1";
    cache.alone = false;
    cache.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmCacheStandResult result = modelnet::SwarmNoteCacheAlone(cache, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(alone_false_want_share_false)
{
    modelnet::SwarmCacheStand cache;
    cache.cache_id = "cache-1";
    cache.alone = false;
    cache.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmCacheStandResult result = modelnet::SwarmNoteCacheAlone(cache, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
