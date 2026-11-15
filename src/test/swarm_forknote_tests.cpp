// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forknote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_forknote_tests, BasicTestingSetup)

static modelnet::SwarmForkNote FilledNote()
{
    modelnet::SwarmForkNote note;
    note.left_id = "left";
    note.right_id = "right";
    note.left_digest = "digest-a";
    note.right_digest = "digest-a";
    note.want_average = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_left_id_is_fork)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.left_id.clear();
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "FORK");
    BOOST_CHECK_EQUAL(err, "FORK");
}

BOOST_AUTO_TEST_CASE(empty_right_id_is_fork)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.right_id.clear();
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "FORK");
    BOOST_CHECK_EQUAL(err, "FORK");
}

BOOST_AUTO_TEST_CASE(empty_left_digest_is_fork)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.left_digest.clear();
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "FORK");
    BOOST_CHECK_EQUAL(err, "FORK");
}

BOOST_AUTO_TEST_CASE(empty_right_digest_is_fork)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.right_digest.clear();
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "FORK");
    BOOST_CHECK_EQUAL(err, "FORK");
}

BOOST_AUTO_TEST_CASE(empty_fields_win_over_want_average)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.left_id.clear();
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "FORK");
    BOOST_CHECK_EQUAL(err, "FORK");
}

BOOST_AUTO_TEST_CASE(want_average_with_equal_digests_is_refused)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "AVERAGE_REFUSED");
    BOOST_CHECK_EQUAL(err, "AVERAGE_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_average_wins_over_divergent_digests)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.right_digest = "digest-b";
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "AVERAGE_REFUSED");
    BOOST_CHECK_EQUAL(err, "AVERAGE_REFUSED");
}

BOOST_AUTO_TEST_CASE(divergent_digests_are_not_averaged)
{
    modelnet::SwarmForkNote note = FilledNote();
    note.right_digest = "digest-b";
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "DIVERGED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(matching_digests_are_noted)
{
    modelnet::SwarmForkNote note = FilledNote();
    std::string err = "prior";
    const modelnet::SwarmForkNoteResult result = modelnet::SwarmNoteFork(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
