// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprompt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notprompt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_prompt_id_is_prompt)
{
    modelnet::SwarmNotPrompt note;
    std::string err = "prior";
    const modelnet::SwarmNotPromptResult result = modelnet::SwarmNoteNotPrompt(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.code, "PROMPT");
    BOOST_CHECK_EQUAL(err, "PROMPT");
}

BOOST_AUTO_TEST_CASE(want_private_is_private_data)
{
    modelnet::SwarmNotPrompt note;
    note.prompt_id = "prompt-1";
    note.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmNotPromptResult result = modelnet::SwarmNoteNotPrompt(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.code, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotPrompt note;
    note.prompt_id = "prompt-1";
    note.want_private = false;
    std::string err = "prior";
    const modelnet::SwarmNotPromptResult result = modelnet::SwarmNoteNotPrompt(note, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.stored, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
