// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno90s.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notno90s_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_spacing_id_is_spacing)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90s note;
    note.seconds = 90;
    note.want_guarantee = true;
    const modelnet::SwarmNotNo90sResult result = modelnet::SwarmNoteNotNo90s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "SPACING");
    BOOST_CHECK_EQUAL(err, "SPACING");
}

BOOST_AUTO_TEST_CASE(seconds_not_90_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90s note;
    note.spacing_id = "spacing-note";
    note.seconds = 89;
    note.want_guarantee = false;
    const modelnet::SwarmNotNo90sResult result = modelnet::SwarmNoteNotNo90s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(seconds_90_with_want_guarantee_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90s note;
    note.spacing_id = "spacing-note";
    note.seconds = 90;
    note.want_guarantee = true;
    const modelnet::SwarmNotNo90sResult result = modelnet::SwarmNoteNotNo90s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(seconds_90_plain_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNo90s note;
    note.spacing_id = "spacing-note";
    note.seconds = 90;
    note.want_guarantee = false;
    const modelnet::SwarmNotNo90sResult result = modelnet::SwarmNoteNotNo90s(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.applied_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
