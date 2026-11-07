// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofetch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofetch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_dep_id_is_dep)
{
    modelnet::SwarmNotNoFetch note;
    std::string err = "prior";
    const modelnet::SwarmNotNoFetchResult result = modelnet::SwarmNoteNotNoFetch(note, err);
    BOOST_CHECK_EQUAL(result.fetched, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "DEP");
    BOOST_CHECK_EQUAL(err, "DEP");
}

BOOST_AUTO_TEST_CASE(want_fetch_is_not_fetched)
{
    modelnet::SwarmNotNoFetch note;
    note.dep_id = "dep-1";
    note.want_fetch = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFetchResult result = modelnet::SwarmNoteNotNoFetch(note, err);
    BOOST_CHECK_EQUAL(result.fetched, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_FETCHED");
    BOOST_CHECK_EQUAL(err, "NOT_FETCHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFetch note;
    note.dep_id = "dep-1";
    note.want_fetch = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFetchResult result = modelnet::SwarmNoteNotNoFetch(note, err);
    BOOST_CHECK_EQUAL(result.fetched, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
