// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_private.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_private_tests, BasicTestingSetup)

static modelnet::SwarmPrivatePrompt NotedPrompt()
{
    modelnet::SwarmPrivatePrompt prompt;
    prompt.node_id = "node-1";
    prompt.operator_allows = false;
    prompt.want_private = false;
    return prompt;
}

static void ExpectRefused(const modelnet::SwarmPrivatePromptResult& result)
{
    BOOST_CHECK(!result.accepted);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_prompt)
{
    modelnet::SwarmPrivatePrompt prompt = NotedPrompt();
    prompt.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPrivatePromptResult result = modelnet::SwarmNotePrivatePrompt(prompt, err);
    ExpectRefused(result);
    BOOST_CHECK_EQUAL(result.code, "PROMPT");
    BOOST_CHECK_EQUAL(err, "PROMPT");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_private_and_allowance)
{
    modelnet::SwarmPrivatePrompt prompt = NotedPrompt();
    prompt.node_id.clear();
    prompt.operator_allows = true;
    prompt.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmPrivatePromptResult result = modelnet::SwarmNotePrivatePrompt(prompt, err);
    ExpectRefused(result);
    BOOST_CHECK_EQUAL(result.code, "PROMPT");
    BOOST_CHECK_EQUAL(err, "PROMPT");
}

BOOST_AUTO_TEST_CASE(private_without_allowance_is_private)
{
    modelnet::SwarmPrivatePrompt prompt = NotedPrompt();
    prompt.want_private = true;
    prompt.operator_allows = false;
    std::string err = "prior";
    const modelnet::SwarmPrivatePromptResult result = modelnet::SwarmNotePrivatePrompt(prompt, err);
    ExpectRefused(result);
    BOOST_CHECK_EQUAL(result.code, "PRIVATE");
    BOOST_CHECK_EQUAL(err, "PRIVATE");
}

BOOST_AUTO_TEST_CASE(want_private_with_allowance_is_held)
{
    modelnet::SwarmPrivatePrompt prompt = NotedPrompt();
    prompt.want_private = true;
    prompt.operator_allows = true;
    std::string err = "prior";
    const modelnet::SwarmPrivatePromptResult result = modelnet::SwarmNotePrivatePrompt(prompt, err);
    ExpectRefused(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(allowance_without_private_is_noted)
{
    modelnet::SwarmPrivatePrompt prompt = NotedPrompt();
    prompt.operator_allows = true;
    prompt.want_private = false;
    std::string err = "prior";
    const modelnet::SwarmPrivatePromptResult result = modelnet::SwarmNotePrivatePrompt(prompt, err);
    ExpectRefused(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmPrivatePrompt prompt = NotedPrompt();
    std::string err = "prior";
    const modelnet::SwarmPrivatePromptResult result = modelnet::SwarmNotePrivatePrompt(prompt, err);
    ExpectRefused(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
