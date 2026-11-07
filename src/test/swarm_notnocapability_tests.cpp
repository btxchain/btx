// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocapability.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocapability_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_action_id_is_action)
{
    modelnet::SwarmNotNoCapability note;
    note.covered = false;
    note.want_act = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapabilityResult result = modelnet::SwarmNoteNotNoCapability(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ACTION");
    BOOST_CHECK_EQUAL(err, "ACTION");
}

BOOST_AUTO_TEST_CASE(covered_false_is_authority_when_want_act_is_false)
{
    modelnet::SwarmNotNoCapability note;
    note.action_id = "action-1";
    note.covered = false;
    note.want_act = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapabilityResult result = modelnet::SwarmNoteNotNoCapability(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "AUTHORITY");
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
}

BOOST_AUTO_TEST_CASE(want_act_is_held)
{
    modelnet::SwarmNotNoCapability note;
    note.action_id = "action-1";
    note.covered = true;
    note.want_act = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapabilityResult result = modelnet::SwarmNoteNotNoCapability(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCapability note;
    note.action_id = "action-1";
    note.covered = true;
    note.want_act = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCapabilityResult result = modelnet::SwarmNoteNotNoCapability(note, err);
    BOOST_CHECK(!result.acted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
