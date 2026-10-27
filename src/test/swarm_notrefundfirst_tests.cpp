// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrefundfirst.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrefundfirst_tests, BasicTestingSetup)

static modelnet::SwarmNotRefundFirst NotedNote()
{
    modelnet::SwarmNotRefundFirst note;
    note.channel_id = "channel-1";
    note.refund_ready = true;
    note.want_count_funding = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotRefundFirst note = NotedNote();
    note.channel_id.clear();
    note.refund_ready = true;
    note.want_count_funding = true;
    std::string err = "prior";
    const modelnet::SwarmNotRefundFirstResult result = modelnet::SwarmNoteNotRefundFirst(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(refund_not_ready_is_unsigned)
{
    modelnet::SwarmNotRefundFirst note = NotedNote();
    note.refund_ready = false;
    note.want_count_funding = false;
    std::string err = "prior";
    const modelnet::SwarmNotRefundFirstResult result = modelnet::SwarmNoteNotRefundFirst(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(want_count_funding_is_unsigned)
{
    modelnet::SwarmNotRefundFirst note = NotedNote();
    note.refund_ready = true;
    note.want_count_funding = true;
    std::string err = "prior";
    const modelnet::SwarmNotRefundFirstResult result = modelnet::SwarmNoteNotRefundFirst(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(plain_ready_note_is_noted)
{
    modelnet::SwarmNotRefundFirst note = NotedNote();
    note.refund_ready = true;
    note.want_count_funding = false;
    std::string err = "prior";
    const modelnet::SwarmNotRefundFirstResult result = modelnet::SwarmNoteNotRefundFirst(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
