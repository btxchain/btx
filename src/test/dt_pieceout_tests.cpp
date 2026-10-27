// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_pieceout/dt_pieceout.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_piecepipe/codes.h>
#include <modelnet/swarm_piecepipe/digest.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectIdle(const modelnet::DtPieceOut& out)
{
    BOOST_CHECK(!out.launched());
    BOOST_CHECK(!out.gpu());
    BOOST_CHECK(!out.broadcast());
    BOOST_CHECK(!out.qualified());
    BOOST_CHECK(!out.compute_proof());
    BOOST_CHECK_EQUAL(out.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(out.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(out.hosts(), static_cast<std::int64_t>(1));
    BOOST_CHECK_EQUAL(out.bytes_moved(), static_cast<std::int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_pieceout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_body_stores_nothing)
{
    modelnet::DtPieceOut out;
    std::string err = "stale";
    ExpectIdle(out);
    BOOST_CHECK(out.artifact().empty());
    BOOST_CHECK_EQUAL(out.piece_count(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(out.manifest_count(), static_cast<std::size_t>(0));

    BOOST_CHECK(!out.Put({}, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPiecePipePiece);
    BOOST_CHECK(out.artifact().empty());
    BOOST_CHECK(out.slice_ids().empty());
    BOOST_CHECK_EQUAL(out.piece_count(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(out.manifest_count(), static_cast<std::size_t>(0));
    BOOST_CHECK(!out.usable(""));

    BOOST_CHECK(!out.Resume("missing", err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPiecePipeManifest);
    BOOST_CHECK_EQUAL(out.manifest_count(), static_cast<std::size_t>(0));

    BOOST_CHECK(!out.Claim(err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK_EQUAL(err, modelnet::DT_PIECEOUT_CLAIM);
    BOOST_CHECK(!out.compute_proof());
    ExpectIdle(out);
}

BOOST_AUTO_TEST_CASE(small_body_splits_and_resumes_usable)
{
    modelnet::DtPieceOut out;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    const std::string id = modelnet::SwarmPiecePipeDigest(body);
    std::string err = "stale";

    BOOST_CHECK(out.Put(body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(out.artifact(), id);
    BOOST_CHECK_EQUAL(out.artifact().size(), static_cast<std::size_t>(96));
    BOOST_CHECK(out.usable(out.artifact()));
    BOOST_CHECK_EQUAL(out.piece_count(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(out.manifest_count(), static_cast<std::size_t>(1));
    const std::vector<std::string> slices = out.slice_ids();
    BOOST_REQUIRE_EQUAL(slices.size(), static_cast<std::size_t>(1));
    BOOST_CHECK(out.has_piece(slices[0]));

    BOOST_CHECK(out.Resume(out.artifact(), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(out.usable(out.artifact()));

    BOOST_CHECK(out.Put(body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(out.artifact(), id);
    BOOST_CHECK_EQUAL(out.piece_count(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(out.manifest_count(), static_cast<std::size_t>(1));
    BOOST_CHECK(out.usable(id));
    ExpectIdle(out);
}

BOOST_AUTO_TEST_CASE(required_slice_drop_is_manifest_and_piece_stays)
{
    modelnet::DtPieceOut out;
    const std::vector<unsigned char> body = {'p', 'i', 'e', 'c', 'e'};
    std::string err = "stale";
    BOOST_REQUIRE(out.Put(body, err));
    const std::vector<std::string> slices = out.slice_ids();
    BOOST_REQUIRE_EQUAL(slices.size(), static_cast<std::size_t>(1));
    const std::string slice = slices[0];
    const std::size_t pieces = out.piece_count();
    BOOST_CHECK(out.has_piece(slice));
    BOOST_CHECK(out.usable(out.artifact()));

    BOOST_CHECK(!out.DropRequired(slice, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPiecePipeManifest);
    BOOST_CHECK(out.has_piece(slice));
    BOOST_CHECK_EQUAL(out.piece_count(), pieces);
    BOOST_CHECK_EQUAL(out.manifest_count(), static_cast<std::size_t>(1));
    BOOST_CHECK(out.usable(out.artifact()));

    BOOST_CHECK(!out.Claim(err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK_EQUAL(err, modelnet::DT_PIECEOUT_CLAIM);
    BOOST_CHECK(!out.compute_proof());
    BOOST_CHECK(out.has_piece(slice));
    ExpectIdle(out);
}

BOOST_AUTO_TEST_SUITE_END()
