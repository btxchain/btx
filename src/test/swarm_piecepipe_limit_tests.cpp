// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/limits.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_piecepipe_limit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(piece_and_body_limits_are_four_and_thirty_two_mib)
{
    BOOST_CHECK_EQUAL(modelnet::kSwarmPiecePipePieceBytes, static_cast<std::size_t>(4194304));
    BOOST_CHECK_EQUAL(modelnet::kSwarmPiecePipeBodyLimit, static_cast<std::size_t>(33554432));
    BOOST_CHECK_EQUAL(modelnet::kSwarmPiecePipeBodyLimit / modelnet::kSwarmPiecePipePieceBytes, static_cast<std::size_t>(8));
}

BOOST_AUTO_TEST_CASE(accept_of_the_body_limit_stores_one_piece)
{
    modelnet::SwarmPiecePipe pipe;
    std::vector<unsigned char> body(modelnet::kSwarmPiecePipeBodyLimit, 0x11);
    body[0] = 0x22;
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_CHECK(pipe.Accept(id, body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pipe.HasPiece(id));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK(!pipe.broadcast());
    BOOST_CHECK(!pipe.launched());
    BOOST_CHECK(!pipe.gpu());
}

BOOST_AUTO_TEST_CASE(accept_over_the_body_limit_is_piece_limit_and_stores_nothing)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> kept = {'k'};
    const std::string kept_id = modelnet::SwarmPiecePipeDigest(kept);
    std::string err;
    BOOST_REQUIRE(pipe.Accept(kept_id, kept, err));
    const std::vector<unsigned char> over(modelnet::kSwarmPiecePipeBodyLimit + 1, 0x11);
    BOOST_CHECK(!pipe.Accept(kept_id, over, err));
    BOOST_CHECK_EQUAL(err, "PIECE_LIMIT");
    BOOST_CHECK(!pipe.Accept("not-a-digest", over, err));
    BOOST_CHECK_EQUAL(err, "PIECE_LIMIT");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(pipe.HasPiece(kept_id));
    BOOST_CHECK(!pipe.Accept(kept_id, kept, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
}

BOOST_AUTO_TEST_CASE(accept_over_the_piece_limit_still_stores_one_body)
{
    modelnet::SwarmPiecePipe pipe;
    std::vector<unsigned char> body(modelnet::kSwarmPiecePipePieceBytes + 1, 0x09);
    body[0] = 0x03;
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_CHECK(pipe.Accept(id, body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
}

BOOST_AUTO_TEST_CASE(split_over_the_body_limit_is_piece_limit_and_stores_nothing)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> kept = {'k'};
    const std::string kept_id = modelnet::SwarmPiecePipeDigest(kept);
    std::string err;
    BOOST_REQUIRE(pipe.Accept(kept_id, kept, err));
    const std::vector<unsigned char> over(modelnet::kSwarmPiecePipeBodyLimit + 1, 0x44);
    BOOST_CHECK(!pipe.Split(over, err));
    BOOST_CHECK_EQUAL(err, "PIECE_LIMIT");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    BOOST_CHECK(pipe.HasPiece(kept_id));
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK(!pipe.broadcast());
}

BOOST_AUTO_TEST_CASE(split_of_the_body_limit_stores_eight_pieces)
{
    modelnet::SwarmPiecePipe pipe;
    std::vector<unsigned char> body(modelnet::kSwarmPiecePipeBodyLimit, 0);
    for (std::size_t i = 0; i < 8; ++i) {
        body[i * modelnet::kSwarmPiecePipePieceBytes] = static_cast<unsigned char>(i + 1);
    }
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_CHECK(pipe.Split(body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!pipe.usable(artifact));
    const std::vector<std::string> ids = pipe.SliceIds(artifact);
    BOOST_REQUIRE_EQUAL(ids.size(), static_cast<std::size_t>(8));
    for (std::size_t i = 0; i < 8; ++i) {
        const std::string slice = modelnet::SwarmPiecePipeDigest(body.data() + (i * modelnet::kSwarmPiecePipePieceBytes), modelnet::kSwarmPiecePipePieceBytes);
        BOOST_CHECK_EQUAL(ids[i], slice);
        BOOST_CHECK(pipe.HasPiece(slice));
        BOOST_CHECK(artifact != slice);
    }
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(8));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(pipe.Resume(artifact, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pipe.usable(artifact));
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK(!pipe.broadcast());
    BOOST_CHECK(!pipe.launched());
    BOOST_CHECK(!pipe.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
