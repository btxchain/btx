// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag01.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag01_tests, BasicTestingSetup)

static modelnet::SwarmFlag01 OpenArtifact()
{
    modelnet::SwarmFlag01 in;
    in.artifact_id = "artifact-1";
    in.hash_len = 32;
    in.license_open = true;
    in.want_pass = false;
    return in;
}

static void ExpectNeverMoved(const modelnet::SwarmFlag01Result& result)
{
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.verified);
}

BOOST_AUTO_TEST_CASE(empty_artifact_id_is_artifact)
{
    modelnet::SwarmFlag01 in = OpenArtifact();
    in.artifact_id.clear();
    in.hash_len = 32;
    in.license_open = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag01Result result = modelnet::SwarmStageAcquire(in, err);
    BOOST_CHECK_EQUAL(result.code, "ARTIFACT");
    BOOST_CHECK(!result.staged);
    BOOST_CHECK(!result.verified);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "ARTIFACT");
}

BOOST_AUTO_TEST_CASE(hash_len_not_32_is_hash)
{
    const int bad_lengths[] = {0, 31, 33, -1};
    for (const int hash_len : bad_lengths) {
        modelnet::SwarmFlag01 in = OpenArtifact();
        in.hash_len = hash_len;
        in.license_open = false;
        in.want_pass = true;
        std::string err = "prior";
        const modelnet::SwarmFlag01Result result = modelnet::SwarmStageAcquire(in, err);
        BOOST_CHECK_EQUAL(result.code, "HASH");
        BOOST_CHECK(!result.staged);
        BOOST_CHECK(!result.verified);
        BOOST_CHECK(!result.passed);
        BOOST_CHECK(!result.bytes_moved);
        BOOST_CHECK(!result.broadcast);
        BOOST_CHECK_EQUAL(err, "HASH");
    }
}

BOOST_AUTO_TEST_CASE(closed_license_is_license)
{
    modelnet::SwarmFlag01 in = OpenArtifact();
    in.license_open = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag01Result result = modelnet::SwarmStageAcquire(in, err);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK(!result.staged);
    BOOST_CHECK(!result.verified);
    BOOST_CHECK(!result.passed);
    ExpectNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag01 in = OpenArtifact();
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag01Result result = modelnet::SwarmStageAcquire(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK(!result.staged);
    BOOST_CHECK(!result.verified);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(open_artifact_is_staged)
{
    modelnet::SwarmFlag01 in = OpenArtifact();
    std::string err = "prior";
    const modelnet::SwarmFlag01Result result = modelnet::SwarmStageAcquire(in, err);
    BOOST_CHECK_EQUAL(result.code, "STAGED");
    BOOST_CHECK(result.staged);
    BOOST_CHECK(!result.verified);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
