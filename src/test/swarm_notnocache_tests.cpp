// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocache.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cache_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCache note;
    note.cache_on = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoCacheResult result = modelnet::SwarmNoteNotNoCache(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hit_ppm, 0);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(cache_off)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCache note;
    note.cache_id = "cache-1";
    note.cache_on = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoCacheResult result = modelnet::SwarmNoteNotNoCache(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hit_ppm, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(want_publish_while_on)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCache note;
    note.cache_id = "cache-1";
    note.cache_on = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoCacheResult result = modelnet::SwarmNoteNotNoCache(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hit_ppm, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(on_and_plain)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCache note;
    note.cache_id = "cache-1";
    note.cache_on = true;
    note.want_publish = false;
    const modelnet::SwarmNotNoCacheResult result = modelnet::SwarmNoteNotNoCache(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hit_ppm, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
