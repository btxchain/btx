// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcacheoff.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcacheoff_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotCacheOff note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotCacheOffResult result = modelnet::SwarmNoteNotCacheOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.delta, 0);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    modelnet::SwarmNotCacheOff note;
    note.run_id = "run-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotCacheOffResult result = modelnet::SwarmNoteNotCacheOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.delta, 0);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotCacheOff note;
    note.run_id = "run-1";
    std::string err = "prior";
    const modelnet::SwarmNotCacheOffResult result = modelnet::SwarmNoteNotCacheOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.delta, 0);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
