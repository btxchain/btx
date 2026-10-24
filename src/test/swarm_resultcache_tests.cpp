// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_resultcache.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_resultcache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_key_or_hash_is_cache)
{
    modelnet::SwarmResultCache cache;
    std::string err = "prior";
    BOOST_CHECK(!cache.Put("", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "CACHE");
    BOOST_CHECK(cache.Get("").empty());

    err = "prior";
    BOOST_CHECK(!cache.Put("job", "", err));
    BOOST_CHECK_EQUAL(err, "CACHE");
    BOOST_CHECK(cache.Get("job").empty());

    err = "prior";
    BOOST_CHECK(!cache.Put("", "", err));
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(first_put_stores_and_same_hash_again)
{
    modelnet::SwarmResultCache cache;
    std::string err = "prior";
    BOOST_CHECK(cache.Put("job", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cache.Get("job"), "hash-a");

    err = "prior";
    BOOST_CHECK(cache.Put("job", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cache.Get("job"), "hash-a");
}

BOOST_AUTO_TEST_CASE(different_hash_is_conflict_and_keeps_first)
{
    modelnet::SwarmResultCache cache;
    std::string err = "prior";
    BOOST_CHECK(cache.Put("job", "hash-a", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!cache.Put("job", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(cache.Get("job"), "hash-a");

    err = "prior";
    BOOST_CHECK(!cache.Put("job", "", err));
    BOOST_CHECK_EQUAL(err, "CACHE");
    BOOST_CHECK_EQUAL(cache.Get("job"), "hash-a");
}

BOOST_AUTO_TEST_CASE(absent_key_is_empty_and_keys_are_independent)
{
    modelnet::SwarmResultCache cache;
    BOOST_CHECK(cache.Get("missing").empty());

    std::string err = "prior";
    BOOST_CHECK(cache.Put("a", "hash-a", err));
    BOOST_CHECK(cache.Put("b", "hash-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cache.Get("a"), "hash-a");
    BOOST_CHECK_EQUAL(cache.Get("b"), "hash-b");
    BOOST_CHECK(cache.Get("c").empty());

    err = "prior";
    BOOST_CHECK(!cache.Put("a", "hash-other", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(cache.Get("a"), "hash-a");
    BOOST_CHECK_EQUAL(cache.Get("b"), "hash-b");
}

BOOST_AUTO_TEST_SUITE_END()
