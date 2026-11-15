// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcachegain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcachegain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_cache)
{
    modelnet::SwarmNotCacheGain note;
    std::string err = "prior";
    const modelnet::SwarmNotCacheGainResult result = modelnet::SwarmNoteNotCacheGain(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotCacheGain note;
    note.page_id = "page-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotCacheGainResult result = modelnet::SwarmNoteNotCacheGain(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotCacheGain note;
    note.page_id = "page-1";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotCacheGainResult result = modelnet::SwarmNoteNotCacheGain(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
