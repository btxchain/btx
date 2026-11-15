// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notspacing.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notspacing_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_height_id_is_height)
{
    std::string err = "prior";
    modelnet::SwarmNotSpacing note;
    note.want_wall_clock = true;
    const modelnet::SwarmNotSpacingResult result = modelnet::SwarmNoteNotSpacing(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "HEIGHT");
    BOOST_CHECK_EQUAL(err, "HEIGHT");
}

BOOST_AUTO_TEST_CASE(want_wall_clock_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotSpacing note;
    note.height_id = "height-spacing";
    note.want_wall_clock = true;
    const modelnet::SwarmNotSpacingResult result = modelnet::SwarmNoteNotSpacing(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(spacing_without_wall_clock_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotSpacing note;
    note.height_id = "height-spacing";
    note.want_wall_clock = false;
    const modelnet::SwarmNotSpacingResult result = modelnet::SwarmNoteNotSpacing(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
