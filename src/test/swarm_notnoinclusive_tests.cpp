// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinclusive.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoinclusive_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cohort_id_is_cohort)
{
    modelnet::SwarmNotNoInclusive note;
    note.cohort_id.clear();
    note.expired = true;
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoInclusiveResult result = modelnet::SwarmNoteNotNoInclusive(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");
}

BOOST_AUTO_TEST_CASE(expired_is_expired)
{
    modelnet::SwarmNotNoInclusive note;
    note.cohort_id = "cohort-1";
    note.expired = true;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoInclusiveResult result = modelnet::SwarmNoteNotNoInclusive(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "EXPIRED");
    BOOST_CHECK_EQUAL(err, "EXPIRED");
}

BOOST_AUTO_TEST_CASE(want_keep_is_held)
{
    modelnet::SwarmNotNoInclusive note;
    note.cohort_id = "cohort-1";
    note.expired = false;
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoInclusiveResult result = modelnet::SwarmNoteNotNoInclusive(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoInclusive note;
    BOOST_CHECK(!note.expired);
    BOOST_CHECK(!note.want_keep);
    note.cohort_id = "cohort-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoInclusiveResult result = modelnet::SwarmNoteNotNoInclusive(note, err);
    BOOST_CHECK(!result.kept);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
