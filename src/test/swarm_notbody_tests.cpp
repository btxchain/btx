// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notbody.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notbody_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_body_id)
{
    modelnet::SwarmNotBody note;
    std::string err = "prior";
    const modelnet::SwarmNotBodyResult result = modelnet::SwarmNoteNotBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "BODY");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "BODY");
}

BOOST_AUTO_TEST_CASE(size_33554433)
{
    modelnet::SwarmNotBody note;
    note.body_id = "body-1";
    note.size_bytes = 33554433;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotBodyResult result = modelnet::SwarmNoteNotBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_store_size_1)
{
    modelnet::SwarmNotBody note;
    note.body_id = "body-1";
    note.size_bytes = 1;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotBodyResult result = modelnet::SwarmNoteNotBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_note_size_32)
{
    modelnet::SwarmNotBody note;
    note.body_id = "body-1";
    note.size_bytes = 32;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotBodyResult result = modelnet::SwarmNoteNotBody(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
