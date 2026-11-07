// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlongbase.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notlongbase_tests, BasicTestingSetup)

static modelnet::SwarmNotLongBase NotedNote()
{
    modelnet::SwarmNotLongBase note;
    note.checkpoint_id = "ckpt-1";
    note.want_execute = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_checkpoint_id_is_checkpoint)
{
    modelnet::SwarmNotLongBase note = NotedNote();
    note.checkpoint_id.clear();
    note.want_execute = true;
    std::string err = "prior";
    const modelnet::SwarmNotLongBaseResult result = modelnet::SwarmNoteNotLongBase(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(want_execute_is_not_executed)
{
    modelnet::SwarmNotLongBase note = NotedNote();
    note.want_execute = true;
    std::string err = "prior";
    const modelnet::SwarmNotLongBaseResult result = modelnet::SwarmNoteNotLongBase(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_EXECUTED");
    BOOST_CHECK_EQUAL(err, "NOT_EXECUTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotLongBase note = NotedNote();
    note.want_execute = false;
    std::string err = "prior";
    const modelnet::SwarmNotLongBaseResult result = modelnet::SwarmNoteNotLongBase(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
