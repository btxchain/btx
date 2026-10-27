// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_closemargin_tests, BasicTestingSetup)

static modelnet::SwarmCloseMargin NotedMargin()
{
    modelnet::SwarmCloseMargin note;
    note.channel_id = "channel-a";
    note.height = 100;
    note.refund_height = 261;
    note.close_margin = 160;
    note.want_new_work = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_margin)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.channel_id.clear();
    note.height = -1;
    note.refund_height = 0;
    note.close_margin = 0;
    note.want_new_work = true;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "MARGIN");
    BOOST_CHECK_EQUAL(err, "MARGIN");
}

BOOST_AUTO_TEST_CASE(negative_height_is_margin)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.height = -1;
    note.want_new_work = true;
    note.close_margin = 1;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "MARGIN");
    BOOST_CHECK_EQUAL(err, "MARGIN");
}

BOOST_AUTO_TEST_CASE(refund_height_below_one_is_margin)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.refund_height = 0;
    note.want_new_work = true;
    note.close_margin = 159;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "MARGIN");
    BOOST_CHECK_EQUAL(err, "MARGIN");
}

BOOST_AUTO_TEST_CASE(wrong_close_margin_is_refused_even_when_want_new_work)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.close_margin = 159;
    note.want_new_work = true;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "MARGIN_REFUSED");
    BOOST_CHECK_EQUAL(err, "MARGIN_REFUSED");
}

BOOST_AUTO_TEST_CASE(close_margin_above_required_is_refused)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.close_margin = 161;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "MARGIN_REFUSED");
    BOOST_CHECK_EQUAL(err, "MARGIN_REFUSED");
}

BOOST_AUTO_TEST_CASE(equality_inside_close_margin_is_stop)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.height = 100;
    note.refund_height = 260;
    note.close_margin = 160;
    note.want_new_work = false;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "STOP");
    BOOST_CHECK_EQUAL(err, "STOP");
}

BOOST_AUTO_TEST_CASE(stop_wins_over_want_new_work)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.height = 100;
    note.refund_height = 260;
    note.close_margin = 160;
    note.want_new_work = true;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "STOP");
    BOOST_CHECK_EQUAL(err, "STOP");
}

BOOST_AUTO_TEST_CASE(want_new_work_is_held_and_does_not_start)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.want_new_work = true;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(outside_close_margin_is_noted_and_does_not_start)
{
    modelnet::SwarmCloseMargin note = NotedMargin();
    note.height = 100;
    note.refund_height = 261;
    note.close_margin = 160;
    note.want_new_work = false;
    std::string err = "prior";
    const modelnet::SwarmCloseMarginResult result = modelnet::SwarmNoteCloseMargin(note, err);
    BOOST_CHECK(!result.work_started);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
