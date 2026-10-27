// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosponsor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosponsor_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSponsor NotedNote()
{
    modelnet::SwarmNotNoSponsor note;
    note.refund_id = "refund-1";
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_refund_id_is_refund)
{
    modelnet::SwarmNotNoSponsor note = NotedNote();
    note.refund_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSponsorResult result = modelnet::SwarmNoteNotNoSponsor(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "REFUND");
    BOOST_CHECK_EQUAL(err, "REFUND");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoSponsor note = NotedNote();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSponsorResult result = modelnet::SwarmNoteNotNoSponsor(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSponsor note = NotedNote();
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSponsorResult result = modelnet::SwarmNoteNotNoSponsor(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
