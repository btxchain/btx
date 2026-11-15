// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoproposer2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoproposer2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoProposer2 NotedNote()
{
    modelnet::SwarmNotNoProposer2 note;
    note.proposer_id = "proposer-1";
    note.want_propose = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_proposer_id_is_proposer)
{
    modelnet::SwarmNotNoProposer2 note = NotedNote();
    note.proposer_id.clear();
    note.want_propose = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProposer2Result result = modelnet::SwarmNoteNotNoProposer2(note, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK_EQUAL(result.code, "PROPOSER");
    BOOST_CHECK_EQUAL(err, "PROPOSER");
}

BOOST_AUTO_TEST_CASE(want_propose_is_held)
{
    modelnet::SwarmNotNoProposer2 note = NotedNote();
    note.want_propose = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProposer2Result result = modelnet::SwarmNoteNotNoProposer2(note, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoProposer2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoProposer2Result result = modelnet::SwarmNoteNotNoProposer2(note, err);
    BOOST_CHECK(!result.proposed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
