// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notbytes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notbytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_bytes)
{
    modelnet::SwarmNotBytes note;
    std::string err = "prior";
    const modelnet::SwarmNotBytesResult result = modelnet::SwarmNoteNotBytes(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "BYTES");
    BOOST_CHECK_EQUAL(err, "BYTES");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotBytes note;
    note.page_id = "page-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotBytesResult result = modelnet::SwarmNoteNotBytes(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotBytes note;
    note.page_id = "page-1";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotBytesResult result = modelnet::SwarmNoteNotBytes(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
