// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalsplit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_evalsplit_tests, BasicTestingSetup)

static modelnet::SwarmEvalSplit FilledNote()
{
    modelnet::SwarmEvalSplit note;
    note.candidate_id = "cand-1";
    note.evaluator_id = "eval-a";
    note.outcome = "pass";
    note.other_evaluator_id = "eval-b";
    note.other_outcome = "pass";
    return note;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_eval)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.candidate_id.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_evaluator_id_is_eval)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.evaluator_id.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_outcome_is_eval)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.outcome.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_other_evaluator_id_is_eval)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.other_evaluator_id.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_other_outcome_is_eval)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.other_outcome.clear();
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_fields_win_over_same_evaluator_and_split)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.candidate_id.clear();
    note.other_evaluator_id = note.evaluator_id;
    note.other_outcome = "fail";
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(same_evaluator_with_matching_outcomes)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.other_evaluator_id = note.evaluator_id;
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
}

BOOST_AUTO_TEST_CASE(same_evaluator_wins_over_split)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.other_evaluator_id = note.evaluator_id;
    note.other_outcome = "fail";
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
}

BOOST_AUTO_TEST_CASE(differing_outcomes_are_split)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    note.other_outcome = "fail";
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(matching_notes_are_agreed_and_unsettled)
{
    modelnet::SwarmEvalSplit note = FilledNote();
    std::string err = "prior";
    const modelnet::SwarmEvalSplitResult result = modelnet::SwarmNoteEvalSplit(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "AGREED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
