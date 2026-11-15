// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_staleepoch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_staleepoch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_coordinator_or_epoch_below_one_is_epoch)
{
    std::string err = "prior";
    modelnet::SwarmStaleEpoch missing;
    missing.stored_epoch = 2;
    missing.resume_epoch = 1;
    missing.want_commit = true;
    const modelnet::SwarmStaleEpochResult no_id = modelnet::SwarmNoteStaleEpoch(missing, err);
    BOOST_CHECK(!no_id.committed);
    BOOST_CHECK_EQUAL(no_id.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmStaleEpoch stored_zero;
    stored_zero.coordinator_id = "coord-a";
    stored_zero.stored_epoch = 0;
    stored_zero.resume_epoch = 1;
    stored_zero.want_commit = true;
    const modelnet::SwarmStaleEpochResult zero_stored = modelnet::SwarmNoteStaleEpoch(stored_zero, err);
    BOOST_CHECK(!zero_stored.committed);
    BOOST_CHECK_EQUAL(zero_stored.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmStaleEpoch stored_negative;
    stored_negative.coordinator_id = "coord-a";
    stored_negative.stored_epoch = -1;
    stored_negative.resume_epoch = 4;
    const modelnet::SwarmStaleEpochResult negative_stored = modelnet::SwarmNoteStaleEpoch(stored_negative, err);
    BOOST_CHECK(!negative_stored.committed);
    BOOST_CHECK_EQUAL(negative_stored.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmStaleEpoch resume_zero;
    resume_zero.coordinator_id = "coord-a";
    resume_zero.stored_epoch = 3;
    resume_zero.resume_epoch = 0;
    resume_zero.want_commit = true;
    const modelnet::SwarmStaleEpochResult zero_resume = modelnet::SwarmNoteStaleEpoch(resume_zero, err);
    BOOST_CHECK(!zero_resume.committed);
    BOOST_CHECK_EQUAL(zero_resume.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");

    modelnet::SwarmStaleEpoch resume_negative;
    resume_negative.coordinator_id = "coord-a";
    resume_negative.stored_epoch = 3;
    resume_negative.resume_epoch = -2;
    const modelnet::SwarmStaleEpochResult negative_resume = modelnet::SwarmNoteStaleEpoch(resume_negative, err);
    BOOST_CHECK(!negative_resume.committed);
    BOOST_CHECK_EQUAL(negative_resume.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");
}

BOOST_AUTO_TEST_CASE(lower_resume_epoch_is_stale_even_when_commit_is_requested)
{
    std::string err = "prior";
    modelnet::SwarmStaleEpoch note;
    note.coordinator_id = "coord-a";
    note.stored_epoch = 5;
    note.resume_epoch = 4;
    note.want_commit = true;
    const modelnet::SwarmStaleEpochResult result = modelnet::SwarmNoteStaleEpoch(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(commit_request_at_stored_epoch_is_refused)
{
    std::string err = "prior";
    modelnet::SwarmStaleEpoch at_stored;
    at_stored.coordinator_id = "coord-a";
    at_stored.stored_epoch = 5;
    at_stored.resume_epoch = 5;
    at_stored.want_commit = true;
    const modelnet::SwarmStaleEpochResult same = modelnet::SwarmNoteStaleEpoch(at_stored, err);
    BOOST_CHECK(!same.committed);
    BOOST_CHECK_EQUAL(same.code, "COMMIT_REFUSED");
    BOOST_CHECK_EQUAL(err, "COMMIT_REFUSED");

    modelnet::SwarmStaleEpoch above_stored;
    above_stored.coordinator_id = "coord-a";
    above_stored.stored_epoch = 5;
    above_stored.resume_epoch = 6;
    above_stored.want_commit = true;
    const modelnet::SwarmStaleEpochResult higher = modelnet::SwarmNoteStaleEpoch(above_stored, err);
    BOOST_CHECK(!higher.committed);
    BOOST_CHECK_EQUAL(higher.code, "COMMIT_REFUSED");
    BOOST_CHECK_EQUAL(err, "COMMIT_REFUSED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err_and_does_not_commit)
{
    std::string err = "prior";
    modelnet::SwarmStaleEpoch same;
    same.coordinator_id = "coord-a";
    same.stored_epoch = 5;
    same.resume_epoch = 5;
    same.want_commit = false;
    const modelnet::SwarmStaleEpochResult at_stored = modelnet::SwarmNoteStaleEpoch(same, err);
    BOOST_CHECK(!at_stored.committed);
    BOOST_CHECK_EQUAL(at_stored.code, "NOTED");
    BOOST_CHECK(err.empty());

    err = "prior";
    modelnet::SwarmStaleEpoch later;
    later.coordinator_id = "coord-a";
    later.stored_epoch = 5;
    later.resume_epoch = 8;
    later.want_commit = false;
    const modelnet::SwarmStaleEpochResult ahead = modelnet::SwarmNoteStaleEpoch(later, err);
    BOOST_CHECK(!ahead.committed);
    BOOST_CHECK_EQUAL(ahead.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
