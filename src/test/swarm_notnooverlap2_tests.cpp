// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnooverlap2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnooverlap2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_timeout_id)
{
    modelnet::SwarmNotNoOverlap2 note;
    note.overlapping = true;
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOverlap2Result result = modelnet::SwarmNoteNotNoOverlap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "TIMEOUT");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(err, "TIMEOUT");
}

BOOST_AUTO_TEST_CASE(overlapping_is_held)
{
    modelnet::SwarmNotNoOverlap2 note;
    note.timeout_id = "timeout-1";
    note.overlapping = true;
    note.want_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoOverlap2Result result = modelnet::SwarmNoteNotNoOverlap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_refund_is_held)
{
    modelnet::SwarmNotNoOverlap2 note;
    note.timeout_id = "timeout-1";
    note.overlapping = false;
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOverlap2Result result = modelnet::SwarmNoteNotNoOverlap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoOverlap2 note;
    note.timeout_id = "timeout-1";
    note.overlapping = false;
    note.want_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoOverlap2Result result = modelnet::SwarmNoteNotNoOverlap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
