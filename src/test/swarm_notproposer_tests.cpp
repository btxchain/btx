// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notproposer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notproposer_tests, BasicTestingSetup)

static modelnet::SwarmNotProposer NotedNote()
{
    modelnet::SwarmNotProposer note;
    note.cycle_id = "cycle-1";
    note.want_propose = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_cycle_id_is_cycle)
{
    modelnet::SwarmNotProposer note = NotedNote();
    note.cycle_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotProposerResult result = modelnet::SwarmNoteNotProposer(note, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.code, "CYCLE");
    BOOST_CHECK_EQUAL(err, "CYCLE");
}

BOOST_AUTO_TEST_CASE(want_propose_is_not_proposed)
{
    modelnet::SwarmNotProposer note = NotedNote();
    note.want_propose = true;
    std::string err = "prior";
    const modelnet::SwarmNotProposerResult result = modelnet::SwarmNoteNotProposer(note, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.code, "NOT_PROPOSED");
    BOOST_CHECK_EQUAL(err, "NOT_PROPOSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotProposer note = NotedNote();
    note.want_propose = false;
    std::string err = "prior";
    const modelnet::SwarmNotProposerResult result = modelnet::SwarmNoteNotProposer(note, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
