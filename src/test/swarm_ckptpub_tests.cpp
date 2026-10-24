// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptpub.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_ckptpub_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_checkpoint_id_or_digest_is_checkpoint)
{
    std::string err = "prior";
    modelnet::SwarmCheckpointNote missing_id;
    missing_id.digest = "digest-a";
    missing_id.body_complete = true;
    missing_id.interrupted = true;
    const modelnet::SwarmCheckpointNoteResult no_id = modelnet::SwarmNoteCheckpoint(missing_id, err);
    BOOST_CHECK(!no_id.published);
    BOOST_CHECK_EQUAL(no_id.code, "CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "CHECKPOINT");

    modelnet::SwarmCheckpointNote missing_digest;
    missing_digest.checkpoint_id = "ckpt-a";
    missing_digest.body_complete = true;
    missing_digest.interrupted = true;
    const modelnet::SwarmCheckpointNoteResult no_digest = modelnet::SwarmNoteCheckpoint(missing_digest, err);
    BOOST_CHECK(!no_digest.published);
    BOOST_CHECK_EQUAL(no_digest.code, "CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(incomplete_body_is_truncated_even_when_interrupted)
{
    std::string err = "prior";
    modelnet::SwarmCheckpointNote incomplete;
    incomplete.checkpoint_id = "ckpt-a";
    incomplete.digest = "digest-a";
    incomplete.body_complete = false;
    incomplete.interrupted = false;
    const modelnet::SwarmCheckpointNoteResult truncated = modelnet::SwarmNoteCheckpoint(incomplete, err);
    BOOST_CHECK(!truncated.published);
    BOOST_CHECK_EQUAL(truncated.code, "TRUNCATED");
    BOOST_CHECK_EQUAL(err, "TRUNCATED");

    incomplete.interrupted = true;
    const modelnet::SwarmCheckpointNoteResult still_truncated = modelnet::SwarmNoteCheckpoint(incomplete, err);
    BOOST_CHECK(!still_truncated.published);
    BOOST_CHECK_EQUAL(still_truncated.code, "TRUNCATED");
    BOOST_CHECK_EQUAL(err, "TRUNCATED");
}

BOOST_AUTO_TEST_CASE(interrupted_complete_body_is_interrupted)
{
    std::string err = "prior";
    modelnet::SwarmCheckpointNote note;
    note.checkpoint_id = "ckpt-a";
    note.digest = "digest-a";
    note.body_complete = true;
    note.interrupted = true;
    const modelnet::SwarmCheckpointNoteResult result = modelnet::SwarmNoteCheckpoint(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "INTERRUPTED");
    BOOST_CHECK_EQUAL(err, "INTERRUPTED");
}

BOOST_AUTO_TEST_CASE(noted_is_not_published)
{
    std::string err = "prior";
    modelnet::SwarmCheckpointNote note;
    note.checkpoint_id = "ckpt-a";
    note.digest = "digest-a";
    note.body_complete = true;
    note.interrupted = false;
    const modelnet::SwarmCheckpointNoteResult result = modelnet::SwarmNoteCheckpoint(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
