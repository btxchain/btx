// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotwonode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotwonode_tests, BasicTestingSetup)

static modelnet::SwarmNotNoTwoNode NotedNote()
{
    modelnet::SwarmNotNoTwoNode note;
    note.job_id = "job-1";
    note.want_train = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_job_id_is_job)
{
    modelnet::SwarmNotNoTwoNode note = NotedNote();
    note.job_id.clear();
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTwoNodeResult result = modelnet::SwarmNoteNotNoTwoNode(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_train_is_unqualified)
{
    modelnet::SwarmNotNoTwoNode note = NotedNote();
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTwoNodeResult result = modelnet::SwarmNoteNotNoTwoNode(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTwoNode note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoTwoNodeResult result = modelnet::SwarmNoteNotNoTwoNode(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
