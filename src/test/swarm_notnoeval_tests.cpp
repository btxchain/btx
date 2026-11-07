// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoeval.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoeval_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_author)
{
    modelnet::SwarmNotNoEval note;
    note.evaluator_id = "evaluator-1";
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalResult result = modelnet::SwarmNoteNotNoEval(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "AUTHOR");
    BOOST_CHECK_EQUAL(err, "AUTHOR");
}

BOOST_AUTO_TEST_CASE(same_ids)
{
    modelnet::SwarmNotNoEval note;
    note.author_id = "author-1";
    note.evaluator_id = "author-1";
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalResult result = modelnet::SwarmNoteNotNoEval(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
}

BOOST_AUTO_TEST_CASE(want_accept_different_ids)
{
    modelnet::SwarmNotNoEval note;
    note.author_id = "author-1";
    note.evaluator_id = "evaluator-1";
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalResult result = modelnet::SwarmNoteNotNoEval(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "NOT_ACCEPTED");
    BOOST_CHECK_EQUAL(err, "NOT_ACCEPTED");
}

BOOST_AUTO_TEST_CASE(plain_different_ids)
{
    modelnet::SwarmNotNoEval note;
    BOOST_CHECK(!note.want_accept);
    note.author_id = "author-1";
    note.evaluator_id = "evaluator-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalResult result = modelnet::SwarmNoteNotNoEval(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
