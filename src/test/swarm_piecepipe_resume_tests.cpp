// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/manifest.h>
#include <modelnet/swarm_piecepipe/resume.h>
#include <modelnet/swarm_piecepipe/store.h>
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

BOOST_FIXTURE_TEST_SUITE(swarm_piecepipe_resume_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_artifact_is_manifest_and_not_usable)
{
    modelnet::SwarmPiecePipe pipe;
    std::string err = "stale";
    BOOST_CHECK(!pipe.Resume("missing", err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!pipe.Resume("", err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!pipe.usable("missing"));
    BOOST_CHECK(!pipe.usable(""));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(an_accepted_piece_is_not_a_manifest)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_REQUIRE(pipe.Accept(id, body, err));
    BOOST_CHECK(!pipe.Resume(id, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!pipe.usable(id));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(0));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(resume_marks_the_artifact_usable_without_moving_bytes)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_REQUIRE(pipe.Split(body, err));
    BOOST_CHECK(!pipe.usable(artifact));
    BOOST_CHECK(pipe.Resume(artifact, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pipe.usable(artifact));
    BOOST_CHECK(pipe.Resume(artifact, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pipe.usable(artifact));
    BOOST_CHECK(!pipe.Resume("other", err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(pipe.usable(artifact));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(pipe.ManifestCount(), static_cast<std::size_t>(1));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(drop_of_a_required_slice_is_manifest_and_resume_still_works)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    std::string err;
    BOOST_REQUIRE(pipe.Split(body, err));
    BOOST_REQUIRE(pipe.Resume(artifact, err));
    BOOST_CHECK(!pipe.Drop(artifact, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(pipe.HasPiece(artifact));
    BOOST_CHECK(pipe.usable(artifact));
    BOOST_CHECK(pipe.Resume(artifact, err));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(drop_of_an_unknown_id_is_piece)
{
    modelnet::SwarmPiecePipe pipe;
    std::string err = "stale";
    BOOST_CHECK(!pipe.Drop("missing", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!pipe.Drop("", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(0));
    ExpectQuiet(pipe);
}

BOOST_AUTO_TEST_CASE(drop_of_an_unreferenced_piece_erases_it)
{
    modelnet::SwarmPiecePipe pipe;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::vector<unsigned char> extra = {'e', 'x', 't', 'r', 'a'};
    const std::string artifact = modelnet::SwarmPiecePipeDigest(body);
    const std::string extra_id = modelnet::SwarmPiecePipeDigest(extra);
    std::string err;
    BOOST_REQUIRE(pipe.Split(body, err));
    BOOST_REQUIRE(pipe.Accept(extra_id, extra, err));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(2));
    BOOST_CHECK(pipe.Drop(extra_id, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!pipe.HasPiece(extra_id));
    BOOST_CHECK(pipe.HasPiece(artifact));
    BOOST_CHECK_EQUAL(pipe.PieceCount(), static_cast<std::size_t>(1));
    BOOST_CHECK(!pipe.Drop(extra_id, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(pipe.Resume(artifact, err));
    BOOST_CHECK(pipe.usable(artifact));
    BOOST_CHECK_EQUAL(pipe.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!pipe.decrypted());
    BOOST_CHECK(!pipe.broadcast());
}

BOOST_AUTO_TEST_CASE(a_missing_slice_is_manifest_and_leaves_usable_false)
{
    modelnet::SwarmPiecePipeStore store;
    modelnet::SwarmPiecePipeManifestBook book;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";
    BOOST_REQUIRE(store.Accept(id, body, err));
    BOOST_REQUIRE(book.Put(id, {id}, err));
    BOOST_CHECK(!modelnet::SwarmPiecePipeUsable(book, store, id));
    BOOST_CHECK(modelnet::SwarmPiecePipeResume(book, store, id, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::SwarmPiecePipeUsable(book, store, id));
    BOOST_REQUIRE(store.erase(id));
    BOOST_CHECK(!modelnet::SwarmPiecePipeResume(book, store, id, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!book.marked_usable(id));
    BOOST_CHECK(!modelnet::SwarmPiecePipeUsable(book, store, id));
    BOOST_CHECK(!modelnet::SwarmPiecePipeResume(book, store, "unknown", err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_SUITE_END()
