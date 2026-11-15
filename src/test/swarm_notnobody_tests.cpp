// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobody.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnobody_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_body_id)
{
    modelnet::SwarmNotNoBody note;
    std::string err = "prior";
    const modelnet::SwarmNotNoBodyResult result = modelnet::SwarmNoteNotNoBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "BODY");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.applied_bytes, 0);
    BOOST_CHECK_EQUAL(err, "BODY");
}

BOOST_AUTO_TEST_CASE(wrong_size)
{
    modelnet::SwarmNotNoBody note;
    note.body_id = "body-1";
    note.size_bytes = 33554431;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBodyResult result = modelnet::SwarmNoteNotNoBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.applied_bytes, 0);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(exact_size_want_store)
{
    modelnet::SwarmNotNoBody note;
    note.body_id = "body-1";
    note.size_bytes = 33554432;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBodyResult result = modelnet::SwarmNoteNotNoBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.applied_bytes, 0);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(exact_size_plain)
{
    modelnet::SwarmNotNoBody note;
    note.body_id = "body-1";
    note.size_bytes = 33554432;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBodyResult result = modelnet::SwarmNoteNotNoBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.applied_bytes, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
