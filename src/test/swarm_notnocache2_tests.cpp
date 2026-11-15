// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocache2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocache2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cache_id_is_cache)
{
    modelnet::SwarmNotNoCache2 note;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCache2Result result = modelnet::SwarmNoteNotNoCache2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(want_share_is_alone)
{
    modelnet::SwarmNotNoCache2 note;
    note.cache_id = "cache-1";
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCache2Result result = modelnet::SwarmNoteNotNoCache2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ALONE");
    BOOST_CHECK_EQUAL(err, "ALONE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCache2 note;
    note.cache_id = "cache-1";
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCache2Result result = modelnet::SwarmNoteNotNoCache2(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
