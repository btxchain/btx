// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottrunc.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nottrunc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotTrunc note;
    std::string err = "prior";
    const modelnet::SwarmNotTruncResult result = modelnet::SwarmNoteNotTrunc(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(want_accept_is_not_shown)
{
    modelnet::SwarmNotTrunc note;
    note.page_id = "page-1";
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotTruncResult result = modelnet::SwarmNoteNotTrunc(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHOWN");
    BOOST_CHECK_EQUAL(err, "NOT_SHOWN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotTrunc note;
    note.page_id = "page-1";
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotTruncResult result = modelnet::SwarmNoteNotTrunc(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
