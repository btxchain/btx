// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprompt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprompt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_prompt_id_is_prompt)
{
    modelnet::SwarmNotNoPrompt note;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPromptResult result = modelnet::SwarmNoteNotNoPrompt(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PROMPT");
    BOOST_CHECK_EQUAL(err, "PROMPT");
}

BOOST_AUTO_TEST_CASE(want_store_is_not_stored)
{
    modelnet::SwarmNotNoPrompt note;
    note.prompt_id = "prompt-1";
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPromptResult result = modelnet::SwarmNoteNotNoPrompt(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_STORED");
    BOOST_CHECK_EQUAL(err, "NOT_STORED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoPrompt note;
    note.prompt_id = "prompt-1";
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPromptResult result = modelnet::SwarmNoteNotNoPrompt(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
