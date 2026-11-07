// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprivate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprivate_tests, BasicTestingSetup)

static modelnet::SwarmNotNoPrivate NotedNote()
{
    modelnet::SwarmNotNoPrivate note;
    note.prompt_id = "prompt-1";
    note.private_prompt = false;
    note.want_store = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoPrivate note = NotedNote();
    note.prompt_id.clear();
    note.private_prompt = true;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPrivateResult result = modelnet::SwarmNoteNotNoPrivate(note, err);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "PROMPT");
    BOOST_CHECK_EQUAL(err, "PROMPT");
}

BOOST_AUTO_TEST_CASE(private_prompt)
{
    modelnet::SwarmNotNoPrivate note = NotedNote();
    note.private_prompt = true;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPrivateResult result = modelnet::SwarmNoteNotNoPrivate(note, err);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_STORED");
    BOOST_CHECK_EQUAL(err, "NOT_STORED");
}

BOOST_AUTO_TEST_CASE(want_store_public_prompt)
{
    modelnet::SwarmNotNoPrivate note = NotedNote();
    note.private_prompt = false;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPrivateResult result = modelnet::SwarmNoteNotNoPrivate(note, err);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_STORED");
    BOOST_CHECK_EQUAL(err, "NOT_STORED");
}

BOOST_AUTO_TEST_CASE(plain_public_prompt)
{
    modelnet::SwarmNotNoPrivate note = NotedNote();
    note.private_prompt = false;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPrivateResult result = modelnet::SwarmNoteNotNoPrivate(note, err);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
