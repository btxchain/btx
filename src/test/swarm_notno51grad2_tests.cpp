// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno51grad2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notno51grad2_tests, BasicTestingSetup)

static modelnet::SwarmNotNo51Grad2 NotedNote()
{
    modelnet::SwarmNotNo51Grad2 note;
    note.vote_id = "vote-1";
    note.majority = false;
    note.want_graduate = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_vote_id_is_vote)
{
    modelnet::SwarmNotNo51Grad2 note = NotedNote();
    note.vote_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNo51Grad2Result result = modelnet::SwarmNoteNotNo51Grad2(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "VOTE");
    BOOST_CHECK_EQUAL(err, "VOTE");
}

BOOST_AUTO_TEST_CASE(majority_is_not_graduated)
{
    // A 51 percent vote does not graduate a model.
    modelnet::SwarmNotNo51Grad2 note = NotedNote();
    note.majority = true;
    note.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNo51Grad2Result result = modelnet::SwarmNoteNotNo51Grad2(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
}

BOOST_AUTO_TEST_CASE(want_graduate_is_held)
{
    modelnet::SwarmNotNo51Grad2 note = NotedNote();
    note.majority = false;
    note.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNo51Grad2Result result = modelnet::SwarmNoteNotNo51Grad2(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNo51Grad2 note = NotedNote();
    note.majority = false;
    note.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNo51Grad2Result result = modelnet::SwarmNoteNotNo51Grad2(note, err);
    BOOST_CHECK(!result.graduated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
