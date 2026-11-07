// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoblock.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoblock_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBlock note;
    note.safety_fail = true;
    note.broad_regression = true;
    note.want_publish = true;
    const modelnet::SwarmNotNoBlockResult result = modelnet::SwarmNoteNotNoBlock(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(safety_fail)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBlock note;
    note.run_id = "run-1";
    note.safety_fail = true;
    note.broad_regression = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoBlockResult result = modelnet::SwarmNoteNotNoBlock(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "BLOCK");
    BOOST_CHECK_EQUAL(err, "BLOCK");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBlock note;
    note.run_id = "run-1";
    note.safety_fail = false;
    note.broad_regression = false;
    note.want_publish = true;
    const modelnet::SwarmNotNoBlockResult result = modelnet::SwarmNoteNotNoBlock(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "BLOCK");
    BOOST_CHECK_EQUAL(err, "BLOCK");
}

BOOST_AUTO_TEST_CASE(plain)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBlock note;
    note.run_id = "run-1";
    note.safety_fail = false;
    note.broad_regression = false;
    note.want_publish = false;
    const modelnet::SwarmNotNoBlockResult result = modelnet::SwarmNoteNotNoBlock(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
