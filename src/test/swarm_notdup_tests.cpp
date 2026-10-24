// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdup.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdup_tests, BasicTestingSetup)

static modelnet::SwarmNotDup NotedNote()
{
    modelnet::SwarmNotDup note;
    note.receipt_id = "receipt-1";
    note.want_accept = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_receipt_id_is_receipt)
{
    modelnet::SwarmNotDup note = NotedNote();
    note.receipt_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotDupResult result = modelnet::SwarmNoteNotDup(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK_EQUAL(err, "RECEIPT");
}

BOOST_AUTO_TEST_CASE(want_accept_is_not_live)
{
    modelnet::SwarmNotDup note = NotedNote();
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotDupResult result = modelnet::SwarmNoteNotDup(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOT_LIVE");
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDup note = NotedNote();
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotDupResult result = modelnet::SwarmNoteNotDup(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
