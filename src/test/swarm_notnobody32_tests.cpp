// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobody32.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnobody32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_body_id)
{
    modelnet::SwarmNotNoBody32 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoBody32Result result = modelnet::SwarmNoteNotNoBody32(note, err);
    BOOST_CHECK_EQUAL(result.code, "BODY");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "BODY");
}

BOOST_AUTO_TEST_CASE(wrong_size)
{
    modelnet::SwarmNotNoBody32 note;
    note.body_id = "body-1";
    note.size_bytes = 33554431;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBody32Result result = modelnet::SwarmNoteNotNoBody32(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(exact_size_want_store)
{
    modelnet::SwarmNotNoBody32 note;
    note.body_id = "body-1";
    note.size_bytes = 33554432;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBody32Result result = modelnet::SwarmNoteNotNoBody32(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(exact_size_plain)
{
    modelnet::SwarmNotNoBody32 note;
    note.body_id = "body-1";
    note.size_bytes = 33554432;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBody32Result result = modelnet::SwarmNoteNotNoBody32(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
