// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoqualgrad2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoqualgrad2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_grade_id_is_grade)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQualGrad2 note;
    note.quality = true;
    note.want_promote = true;
    const modelnet::SwarmNotNoQualGrad2Result result = modelnet::SwarmNoteNotNoQualGrad2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "GRADE");
    BOOST_CHECK_EQUAL(err, "GRADE");
}

BOOST_AUTO_TEST_CASE(quality_without_want_promote_is_not_promoted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQualGrad2 note;
    note.grade_id = "grade-a";
    note.quality = true;
    note.want_promote = false;
    const modelnet::SwarmNotNoQualGrad2Result result = modelnet::SwarmNoteNotNoQualGrad2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "NOT_PROMOTED");
    BOOST_CHECK_EQUAL(err, "NOT_PROMOTED");
}

BOOST_AUTO_TEST_CASE(want_promote_without_quality_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQualGrad2 note;
    note.grade_id = "grade-a";
    note.quality = false;
    note.want_promote = true;
    const modelnet::SwarmNotNoQualGrad2Result result = modelnet::SwarmNoteNotNoQualGrad2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_without_quality_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQualGrad2 note;
    note.grade_id = "grade-a";
    note.quality = false;
    note.want_promote = false;
    const modelnet::SwarmNotNoQualGrad2Result result = modelnet::SwarmNoteNotNoQualGrad2(note, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
