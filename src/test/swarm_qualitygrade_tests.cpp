// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_qualitygrade.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_qualitygrade_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_grade_id_is_grade)
{
    std::string err = "prior";
    modelnet::SwarmQualityGrade grade;
    grade.want_promote = true;
    const modelnet::SwarmQualityGradeResult result = modelnet::SwarmNoteQualityGrade(grade, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "GRADE");
    BOOST_CHECK_EQUAL(err, "GRADE");
}

BOOST_AUTO_TEST_CASE(want_promote_is_held)
{
    std::string err = "prior";
    modelnet::SwarmQualityGrade grade;
    grade.grade_id = "grade-1";
    grade.want_promote = true;
    const modelnet::SwarmQualityGradeResult result = modelnet::SwarmNoteQualityGrade(grade, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmQualityGrade grade;
    grade.grade_id = "grade-1";
    grade.want_promote = false;
    const modelnet::SwarmQualityGradeResult result = modelnet::SwarmNoteQualityGrade(grade, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
