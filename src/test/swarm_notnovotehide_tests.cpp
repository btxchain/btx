// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovotehide.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnovotehide_tests, BasicTestingSetup)

static modelnet::SwarmNotNoVoteHide NotedNote()
{
    modelnet::SwarmNotNoVoteHide note;
    note.chain_id = "chain-1";
    note.majority = false;
    note.want_hide = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_chain_id_is_chain)
{
    modelnet::SwarmNotNoVoteHide note = NotedNote();
    note.chain_id.clear();
    note.majority = true;
    note.want_hide = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteHideResult result = modelnet::SwarmNoteNotNoVoteHide(note, err);
    BOOST_CHECK(!result.hidden);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "CHAIN");
    BOOST_CHECK_EQUAL(err, "CHAIN");
}

BOOST_AUTO_TEST_CASE(majority_is_visible)
{
    // A 51 percent vote does not hide a head and does not graduate a candidate.
    modelnet::SwarmNotNoVoteHide note = NotedNote();
    note.majority = true;
    note.want_hide = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteHideResult result = modelnet::SwarmNoteNotNoVoteHide(note, err);
    BOOST_CHECK(!result.hidden);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "VISIBLE");
    BOOST_CHECK_EQUAL(err, "VISIBLE");
}

BOOST_AUTO_TEST_CASE(want_hide_is_held)
{
    modelnet::SwarmNotNoVoteHide note = NotedNote();
    note.majority = false;
    note.want_hide = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteHideResult result = modelnet::SwarmNoteNotNoVoteHide(note, err);
    BOOST_CHECK(!result.hidden);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoVoteHide note = NotedNote();
    note.majority = false;
    note.want_hide = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteHideResult result = modelnet::SwarmNoteNotNoVoteHide(note, err);
    BOOST_CHECK(!result.hidden);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
