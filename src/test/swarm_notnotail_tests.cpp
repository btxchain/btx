// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotail.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotail_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_output_id)
{
    modelnet::SwarmNotNoTail note;
    std::string err = "prior";
    const modelnet::SwarmNotNoTailResult result = modelnet::SwarmNoteNotNoTail(note, err);
    BOOST_CHECK_EQUAL(result.code, "OUTPUT");
    BOOST_CHECK(!result.complete);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "OUTPUT");
}

BOOST_AUTO_TEST_CASE(truncated)
{
    modelnet::SwarmNotNoTail note;
    note.output_id = "output-1";
    note.truncated = true;
    note.want_complete = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTailResult result = modelnet::SwarmNoteNotNoTail(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPLETE");
    BOOST_CHECK(!result.complete);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "NOT_COMPLETE");
}

BOOST_AUTO_TEST_CASE(want_complete_while_not_truncated)
{
    modelnet::SwarmNotNoTail note;
    note.output_id = "output-1";
    note.truncated = false;
    note.want_complete = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTailResult result = modelnet::SwarmNoteNotNoTail(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPLETE");
    BOOST_CHECK(!result.complete);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "NOT_COMPLETE");
}

BOOST_AUTO_TEST_CASE(plain)
{
    modelnet::SwarmNotNoTail note;
    note.output_id = "output-1";
    note.truncated = false;
    note.want_complete = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTailResult result = modelnet::SwarmNoteNotNoTail(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.complete);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
