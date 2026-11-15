// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cache_id)
{
    modelnet::SwarmNotNoHit note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHitResult result = modelnet::SwarmNoteNotNoHit(note, err);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hit_ppm, 0);
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    modelnet::SwarmNotNoHit note;
    note.cache_id = "cache-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHitResult result = modelnet::SwarmNoteNotNoHit(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hit_ppm, 0);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoHit note;
    note.cache_id = "cache-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoHitResult result = modelnet::SwarmNoteNotNoHit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.hit_ppm, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
