// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocachealone.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocachealone_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cache_id_is_cache)
{
    modelnet::SwarmNotNoCacheAlone note;
    note.coupled = true;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCacheAloneResult result = modelnet::SwarmNoteNotNoCacheAlone(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(coupled_is_stands_alone_when_want_share_is_false)
{
    modelnet::SwarmNotNoCacheAlone note;
    note.cache_id = "cache-1";
    note.coupled = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCacheAloneResult result = modelnet::SwarmNoteNotNoCacheAlone(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "STANDS_ALONE");
    BOOST_CHECK_EQUAL(err, "STANDS_ALONE");
}

BOOST_AUTO_TEST_CASE(want_share_is_held)
{
    modelnet::SwarmNotNoCacheAlone note;
    note.cache_id = "cache-1";
    note.coupled = false;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCacheAloneResult result = modelnet::SwarmNoteNotNoCacheAlone(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCacheAlone note;
    note.cache_id = "cache-1";
    note.coupled = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCacheAloneResult result = modelnet::SwarmNoteNotNoCacheAlone(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
