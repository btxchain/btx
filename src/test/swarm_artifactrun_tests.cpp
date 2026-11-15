// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifactrun/swarm_artifactrun.h>
#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/limits.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmArtifactRun& run)
{
    BOOST_CHECK_EQUAL(run.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!run.launched());
    BOOST_CHECK(!run.gpu());
    BOOST_CHECK(!run.broadcast());
    BOOST_CHECK_EQUAL(run.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_artifactrun_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(piece_bound_is_the_pipeline_limit)
{
    BOOST_CHECK_EQUAL(modelnet::kSwarmPiecePipePieceBytes, static_cast<std::size_t>(4194304));
}

BOOST_AUTO_TEST_CASE(empty_body_is_piece)
{
    modelnet::SwarmArtifactRun run;
    std::string err = "stale";
    BOOST_CHECK(!run.AcceptBody("id", {}, "id", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!run.SplitBody({}, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!run.Close("id", err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!run.closed());
    BOOST_CHECK(!run.loaded());
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(pipeline_rejects_a_digest_that_does_not_match)
{
    modelnet::SwarmArtifactRun run;
    const std::vector<unsigned char> body{'a', 'b'};
    std::string err = "stale";
    BOOST_CHECK(!run.AcceptBody("ab", body, "ab", err));
    BOOST_CHECK_EQUAL(err, "PIECE_DIGEST");
    BOOST_CHECK(!run.closed());
    BOOST_CHECK(!run.loaded());
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(complete_before_close_is_manifest_then_load_and_conflict)
{
    modelnet::SwarmArtifactRun run;
    const std::vector<unsigned char> body{'a', 'b'};
    std::vector<unsigned char> other = body;
    other[1] = 'c';
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";

    BOOST_REQUIRE(run.AcceptBody(id, body, id, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(run.SplitBody(body, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!run.Complete(id, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!run.closed());
    BOOST_CHECK(!run.closed(id));
    BOOST_CHECK(!run.Generation(id, body, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(run.generation_bytes(id).empty());
    BOOST_CHECK(!run.Load(id, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!run.loaded());
    BOOST_CHECK(!run.launched());

    BOOST_REQUIRE(run.Close(id, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(run.closed());
    BOOST_CHECK(run.closed(id));
    BOOST_CHECK(!run.Complete("other", err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(run.Complete(id, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!run.Generation(id, {}, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_REQUIRE(run.Generation(id, body, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(run.Load(id, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(run.loaded());
    BOOST_CHECK(!run.launched());
    BOOST_CHECK(run.generation_bytes(id) == body);

    BOOST_CHECK(!run.Generation(id, other, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(run.generation_bytes(id) == body);
    BOOST_CHECK(!run.Generation(id, body, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(run.generation_bytes(id) == body);
    BOOST_CHECK(run.loaded());
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_SUITE_END()
