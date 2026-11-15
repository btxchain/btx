// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdrot2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoholdrot2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_holdout_id_is_holdout)
{
    modelnet::SwarmNotNoHoldRot2 note;
    note.holdout_id.clear();
    note.fixed_set = true;
    note.want_rotate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRot2Result result = modelnet::SwarmNoteNotNoHoldRot2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK_EQUAL(result.code, "HOLDOUT");
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
}

BOOST_AUTO_TEST_CASE(fixed_set_is_not_rotating)
{
    modelnet::SwarmNotNoHoldRot2 note;
    note.holdout_id = "holdout-1";
    note.fixed_set = true;
    note.want_rotate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRot2Result result = modelnet::SwarmNoteNotNoHoldRot2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROTATING");
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
}

BOOST_AUTO_TEST_CASE(want_rotate_is_held)
{
    modelnet::SwarmNotNoHoldRot2 note;
    note.holdout_id = "holdout-1";
    note.fixed_set = false;
    note.want_rotate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRot2Result result = modelnet::SwarmNoteNotNoHoldRot2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoHoldRot2 note;
    note.holdout_id = "holdout-1";
    note.fixed_set = false;
    note.want_rotate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRot2Result result = modelnet::SwarmNoteNotNoHoldRot2(note, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
