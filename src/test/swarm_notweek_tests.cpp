// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notweek.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notweek_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_window_id_is_window)
{
    std::string err = "prior";
    modelnet::SwarmNotWeek note;
    note.blocks = 6720;
    note.want_guarantee = true;
    const modelnet::SwarmNotWeekResult result = modelnet::SwarmNoteNotWeek(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "WINDOW");
    BOOST_CHECK_EQUAL(err, "WINDOW");
}

BOOST_AUTO_TEST_CASE(blocks_6719_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotWeek note;
    note.window_id = "window-week";
    note.blocks = 6719;
    note.want_guarantee = false;
    const modelnet::SwarmNotWeekResult result = modelnet::SwarmNoteNotWeek(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_6721_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotWeek note;
    note.window_id = "window-week";
    note.blocks = 6721;
    note.want_guarantee = false;
    const modelnet::SwarmNotWeekResult result = modelnet::SwarmNoteNotWeek(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_6720_with_want_guarantee_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotWeek note;
    note.window_id = "window-week";
    note.blocks = 6720;
    note.want_guarantee = true;
    const modelnet::SwarmNotWeekResult result = modelnet::SwarmNoteNotWeek(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_6720_plain_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotWeek note;
    note.window_id = "window-week";
    note.blocks = 6720;
    note.want_guarantee = false;
    const modelnet::SwarmNotWeekResult result = modelnet::SwarmNoteNotWeek(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
