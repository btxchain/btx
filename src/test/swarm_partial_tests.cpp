// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_partial.h>
#include <cstdint>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_partial_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_bad_expected_or_negative_received_is_artifact)
{
    std::string err = "prior";
    modelnet::SwarmPartialArtifact missing_id;
    missing_id.expected_pieces = 4;
    missing_id.received_pieces = 4;
    missing_id.digest_ok = true;
    const modelnet::SwarmPartialResult no_id = modelnet::SwarmNotePartialArtifact(missing_id, err);
    BOOST_CHECK(!no_id.complete);
    BOOST_CHECK_EQUAL(no_id.code, "ARTIFACT");
    BOOST_CHECK_EQUAL(err, "ARTIFACT");

    modelnet::SwarmPartialArtifact zero_expected;
    zero_expected.artifact_id = "artifact-a";
    zero_expected.expected_pieces = 0;
    zero_expected.received_pieces = 0;
    zero_expected.digest_ok = true;
    const modelnet::SwarmPartialResult no_expected = modelnet::SwarmNotePartialArtifact(zero_expected, err);
    BOOST_CHECK(!no_expected.complete);
    BOOST_CHECK_EQUAL(no_expected.code, "ARTIFACT");
    BOOST_CHECK_EQUAL(err, "ARTIFACT");

    modelnet::SwarmPartialArtifact negative_expected;
    negative_expected.artifact_id = "artifact-a";
    negative_expected.expected_pieces = -1;
    negative_expected.received_pieces = 1;
    negative_expected.digest_ok = true;
    const modelnet::SwarmPartialResult bad_expected = modelnet::SwarmNotePartialArtifact(negative_expected, err);
    BOOST_CHECK(!bad_expected.complete);
    BOOST_CHECK_EQUAL(bad_expected.code, "ARTIFACT");
    BOOST_CHECK_EQUAL(err, "ARTIFACT");

    modelnet::SwarmPartialArtifact negative_received;
    negative_received.artifact_id = "artifact-a";
    negative_received.expected_pieces = 4;
    negative_received.received_pieces = -1;
    negative_received.digest_ok = true;
    const modelnet::SwarmPartialResult bad_received = modelnet::SwarmNotePartialArtifact(negative_received, err);
    BOOST_CHECK(!bad_received.complete);
    BOOST_CHECK_EQUAL(bad_received.code, "ARTIFACT");
    BOOST_CHECK_EQUAL(err, "ARTIFACT");
}

BOOST_AUTO_TEST_CASE(short_count_is_partial_even_when_digest_ok)
{
    std::string err = "prior";
    modelnet::SwarmPartialArtifact short_count;
    short_count.artifact_id = "artifact-a";
    short_count.expected_pieces = 4;
    short_count.received_pieces = 3;
    short_count.digest_ok = true;
    const modelnet::SwarmPartialResult result = modelnet::SwarmNotePartialArtifact(short_count, err);
    BOOST_CHECK(!result.complete);
    BOOST_CHECK_EQUAL(result.code, "PARTIAL");
    BOOST_CHECK_EQUAL(err, "PARTIAL");

    short_count.digest_ok = false;
    const modelnet::SwarmPartialResult still_partial = modelnet::SwarmNotePartialArtifact(short_count, err);
    BOOST_CHECK(!still_partial.complete);
    BOOST_CHECK_EQUAL(still_partial.code, "PARTIAL");
    BOOST_CHECK_EQUAL(err, "PARTIAL");
}

BOOST_AUTO_TEST_CASE(extra_pieces_are_partial)
{
    std::string err = "prior";
    modelnet::SwarmPartialArtifact extra;
    extra.artifact_id = "artifact-a";
    extra.expected_pieces = 4;
    extra.received_pieces = 5;
    extra.digest_ok = false;
    const modelnet::SwarmPartialResult result = modelnet::SwarmNotePartialArtifact(extra, err);
    BOOST_CHECK(!result.complete);
    BOOST_CHECK_EQUAL(result.code, "PARTIAL");
    BOOST_CHECK_EQUAL(err, "PARTIAL");

    extra.digest_ok = true;
    const modelnet::SwarmPartialResult still_partial = modelnet::SwarmNotePartialArtifact(extra, err);
    BOOST_CHECK(!still_partial.complete);
    BOOST_CHECK_EQUAL(still_partial.code, "PARTIAL");
    BOOST_CHECK_EQUAL(err, "PARTIAL");
}

BOOST_AUTO_TEST_CASE(matching_count_without_digest_is_digest)
{
    std::string err = "prior";
    modelnet::SwarmPartialArtifact artifact;
    artifact.artifact_id = "artifact-a";
    artifact.expected_pieces = 4;
    artifact.received_pieces = 4;
    artifact.digest_ok = false;
    const modelnet::SwarmPartialResult result = modelnet::SwarmNotePartialArtifact(artifact, err);
    BOOST_CHECK(!result.complete);
    BOOST_CHECK_EQUAL(result.code, "DIGEST");
    BOOST_CHECK_EQUAL(err, "DIGEST");
}

BOOST_AUTO_TEST_CASE(held_is_not_complete)
{
    std::string err = "prior";
    modelnet::SwarmPartialArtifact artifact;
    artifact.artifact_id = "artifact-a";
    artifact.expected_pieces = 4;
    artifact.received_pieces = 4;
    artifact.digest_ok = true;
    const modelnet::SwarmPartialResult result = modelnet::SwarmNotePartialArtifact(artifact, err);
    BOOST_CHECK(!result.complete);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
