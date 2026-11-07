// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofsdp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofsdp_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFsdp NotedNote()
{
    modelnet::SwarmNotNoFsdp note;
    note.step_id = "step-1";
    note.want_distributed = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_step_id_is_step)
{
    modelnet::SwarmNotNoFsdp note = NotedNote();
    note.step_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoFsdpResult result = modelnet::SwarmNoteNotNoFsdp(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(want_distributed_is_not_distributed)
{
    modelnet::SwarmNotNoFsdp note = NotedNote();
    note.want_distributed = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFsdpResult result = modelnet::SwarmNoteNotNoFsdp(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.code, "NOT_DISTRIBUTED");
    BOOST_CHECK_EQUAL(err, "NOT_DISTRIBUTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFsdp note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoFsdpResult result = modelnet::SwarmNoteNotNoFsdp(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
