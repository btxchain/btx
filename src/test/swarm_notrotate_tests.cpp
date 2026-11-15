// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrotate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrotate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_suite_id_is_suite)
{
    modelnet::SwarmNotRotate note;
    std::string err = "prior";
    const modelnet::SwarmNotRotateResult result = modelnet::SwarmNoteNotRotate(note, err);
    BOOST_CHECK_EQUAL(result.rotated, false);
    BOOST_CHECK_EQUAL(result.leaked, false);
    BOOST_CHECK_EQUAL(result.code, "SUITE");
    BOOST_CHECK_EQUAL(err, "SUITE");
}

BOOST_AUTO_TEST_CASE(want_rotate_is_not_rotated)
{
    modelnet::SwarmNotRotate note;
    note.suite_id = "suite-1";
    note.want_rotate = true;
    std::string err = "prior";
    const modelnet::SwarmNotRotateResult result = modelnet::SwarmNoteNotRotate(note, err);
    BOOST_CHECK_EQUAL(result.rotated, false);
    BOOST_CHECK_EQUAL(result.leaked, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROTATED");
    BOOST_CHECK_EQUAL(err, "NOT_ROTATED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRotate note;
    note.suite_id = "suite-1";
    note.want_rotate = false;
    std::string err = "prior";
    const modelnet::SwarmNotRotateResult result = modelnet::SwarmNoteNotRotate(note, err);
    BOOST_CHECK_EQUAL(result.rotated, false);
    BOOST_CHECK_EQUAL(result.leaked, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
