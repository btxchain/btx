// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnooutpoint2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnooutpoint2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_dispute_id_is_dispute)
{
    std::string err = "prior";
    modelnet::SwarmNotNoOutpoint2 note;
    note.want_settle = true;
    const modelnet::SwarmNotNoOutpoint2Result result = modelnet::SwarmNoteNotNoOutpoint2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "DISPUTE");
    BOOST_CHECK_EQUAL(err, "DISPUTE");
}

BOOST_AUTO_TEST_CASE(want_settle_is_not_settled)
{
    std::string err = "prior";
    modelnet::SwarmNotNoOutpoint2 note;
    note.dispute_id = "dispute-1";
    note.want_settle = true;
    const modelnet::SwarmNotNoOutpoint2Result result = modelnet::SwarmNoteNotNoOutpoint2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoOutpoint2 note;
    note.dispute_id = "dispute-1";
    note.want_settle = false;
    const modelnet::SwarmNotNoOutpoint2Result result = modelnet::SwarmNoteNotNoOutpoint2(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
