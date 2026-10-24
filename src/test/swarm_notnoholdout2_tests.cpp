// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdout2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoholdout2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_split_id_is_split)
{
    modelnet::SwarmNotNoHoldout2 note;
    note.split_id.clear();
    note.fixed = true;
    note.want_rotate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldout2Result result = modelnet::SwarmNoteNotNoHoldout2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(fixed_is_not_rotating)
{
    modelnet::SwarmNotNoHoldout2 note;
    note.split_id = "split-1";
    note.fixed = true;
    note.want_rotate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldout2Result result = modelnet::SwarmNoteNotNoHoldout2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROTATING");
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
}

BOOST_AUTO_TEST_CASE(want_rotate_is_held)
{
    modelnet::SwarmNotNoHoldout2 note;
    note.split_id = "split-1";
    note.fixed = false;
    note.want_rotate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldout2Result result = modelnet::SwarmNoteNotNoHoldout2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoHoldout2 note;
    note.split_id = "split-1";
    note.fixed = false;
    note.want_rotate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldout2Result result = modelnet::SwarmNoteNotNoHoldout2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
