// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdtime.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoholdtime_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_dispute_id_is_dispute)
{
    modelnet::SwarmNotNoHoldTime note;
    note.dispute_id.clear();
    note.overlap = true;
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldTimeResult result = modelnet::SwarmNoteNotNoHoldTime(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.code, "DISPUTE");
    BOOST_CHECK_EQUAL(err, "DISPUTE");
}

BOOST_AUTO_TEST_CASE(overlap_is_held)
{
    modelnet::SwarmNotNoHoldTime note;
    note.dispute_id = "dispute-1";
    note.overlap = true;
    note.want_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldTimeResult result = modelnet::SwarmNoteNotNoHoldTime(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_refund_is_held)
{
    modelnet::SwarmNotNoHoldTime note;
    note.dispute_id = "dispute-1";
    note.overlap = false;
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldTimeResult result = modelnet::SwarmNoteNotNoHoldTime(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_is_noted)
{
    modelnet::SwarmNotNoHoldTime note;
    note.dispute_id = "dispute-1";
    note.overlap = false;
    note.want_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldTimeResult result = modelnet::SwarmNoteNotNoHoldTime(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
