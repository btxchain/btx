// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocachealone2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocachealone2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cache_id)
{
    modelnet::SwarmNotNoCacheAlone2 note;
    std::string err = "stale";
    const modelnet::SwarmNotNoCacheAlone2Result result = modelnet::SwarmNoteNotNoCacheAlone2(note, err);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(want_share_true)
{
    modelnet::SwarmNotNoCacheAlone2 note;
    note.cache_id = "cache-1";
    note.want_share = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoCacheAlone2Result result = modelnet::SwarmNoteNotNoCacheAlone2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_empty_nor_want_share)
{
    modelnet::SwarmNotNoCacheAlone2 note;
    note.cache_id = "cache-1";
    note.want_share = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoCacheAlone2Result result = modelnet::SwarmNoteNotNoCacheAlone2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
