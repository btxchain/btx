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

namespace {

void ExpectQuiet(const modelnet::SwarmPiecePipe& pipe)
{
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK(!pipe.broadcast());
    BOOST_CHECK(!pipe.launched());
    BOOST_CHECK(!pipe.gpu());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_piecepipe_split_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_body_is_piece_and_stores_nothing)
{
    modelnet::SwarmPiecePipe pipe;
    std::string err = "stale";
    BOOST_CHECK(!pipe.Split({}, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(five_byte_body_is_one_piece_and_the_artifact_id_is_that_piece)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_CHECK(pipe.Split(body, err));
    BOOST_CHECK(err.empty());
    const std::vector<std::string> ids = pipe.SliceIds(artifact);
    BOOST_REQUIRE_EQUAL(ids.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(ids[0], artifact);
    BOOST_CHECK(pipe.HasPiece(artifact));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(!pipe.usable(artifact));
    BOOST_CHECK(!pipe.Accept(artifact, body, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(exact_piece_limit_is_one_slice_with_the_same_id)
{
    modelnet::SwarmPiecePipe pipe;
    std::vector<unsigned char> body(modelnet::kSwarmPiecePipePieceBytes, 0x7e);
    body[10] = 0x01;
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_CHECK(pipe.Split(body, err));
    const std::vector<std::string> ids = pipe.SliceIds(artifact);
    BOOST_REQUIRE_EQUAL(ids.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(ids[0], artifact);
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(!pipe.usable(artifact));
}

BOOST_AUTO_TEST_CASE(one_past_the_piece_limit_is_two_pieces)
{
    modelnet::SwarmPiecePipe pipe;
    std::vector<unsigned char> body(modelnet::kSwarmPiecePipePieceBytes + 1, 0);
    body[0] = 1;
    body[modelnet::kSwarmPiecePipePieceBytes] = 2;
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    const std::string first = modelnet::SwarmPiecePipeDigest(body.data(), modelnet::kSwarmPiecePipePieceBytes);
    const std::string second = modelnet::SwarmPiecePipeDigest(body.data() + modelnet::kSwarmPiecePipePieceBytes, 1);
    BOOST_CHECK(artifact != first);
    BOOST_CHECK(first != second);
    std::string err;
    BOOST_CHECK(pipe.Split(body, err));
    BOOST_CHECK(err.empty());
    const std::vector<std::string> ids = pipe.SliceIds(artifact);
    BOOST_REQUIRE_EQUAL(ids.size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(ids[0], first);
    BOOST_CHECK_EQUAL(ids[1], second);
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(pipe.HasPiece(first));
    BOOST_CHECK(pipe.HasPiece(second));
    BOOST_CHECK(!pipe.HasPiece(artifact));
    std::vector<unsigned char> first_body(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(modelnet::kSwarmPiecePipePieceBytes));
    const std::vector<unsigned char> second_body = {2};
    BOOST_CHECK(!pipe.Accept(first, first_body, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!pipe.Accept(second, second_body, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!pipe.Drop(artifact, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!pipe.usable(artifact));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(splitting_the_same_body_again_keeps_one_manifest)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_REQUIRE(pipe.Split(body, err));
    BOOST_REQUIRE(pipe.Resume(artifact, err));
    BOOST_CHECK(pipe.usable(artifact));
    BOOST_CHECK(pipe.Split(body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(pipe.usable(artifact));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(two_bodies_store_two_manifests)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> left = {'l', 'e', 'f', 't', '1'};
    const std::vector<unsigned char> right = {'r', 'i', 'g', 'h', 't'};
    const std::string left_id = modelnet::SwarmPiecePipeDigest(left);
    const std::string right_id = modelnet::SwarmPiecePipeDigest(right);
    std::string err;
    BOOST_CHECK(pipe.Split(left, err));
    BOOST_CHECK(pipe.Split(right, err));
    BOOST_CHECK(left_id != right_id);
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(pipe.SliceIds(left_id).size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.SliceIds(right_id).size(), static_cast<std::size_t>(1));
    BOOST_CHECK(pipe.SliceIds("missing").empty());
}

BOOST_AUTO_TEST_CASE(identical_slices_share_one_stored_piece)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body(modelnet::kSwarmPiecePipePieceBytes * 2, 0xab);
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    const std::string slice = modelnet::SwarmPiecePipeDigest(body.data(), modelnet::kSwarmPiecePipePieceBytes);
    std::string err;
    BOOST_CHECK(pipe.Split(body, err));
    const std::vector<std::string> ids = pipe.SliceIds(artifact);
    BOOST_REQUIRE_EQUAL(ids.size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(ids[0], slice);
    BOOST_CHECK_EQUAL(ids[1], slice);
    BOOST_CHECK(artifact != slice);
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(!pipe.Drop(slice, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(pipe.HasPiece(slice));
    BOOST_CHECK(pipe.Resume(artifact, err));
    BOOST_CHECK(pipe.usable(artifact));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(split_of_an_already_accepted_piece_does_not_duplicate_it)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_REQUIRE(pipe.Accept(id, body, err));
    BOOST_CHECK(pipe.Split(body, err));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(!pipe.Drop(id, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
