// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/artifact.h>
#include <modelnet/swarm_artifact/pieces.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_artifact_plane_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(capture_keeps_the_first_bytes)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
    BOOST_REQUIRE(!plane.has_capture());

    BOOST_REQUIRE(plane.Capture(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has_capture());
    const std::string first = plane.captured();
    BOOST_REQUIRE(!first.empty());
    BOOST_REQUIRE(first.rfind("v1|INTEGER_MODEL|", 0) == 0);
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    BOOST_CHECK(!plane.Capture(err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.captured() == first);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.joined());
}

BOOST_AUTO_TEST_CASE(split_rejects_empty_capture_then_chunks)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";

    BOOST_CHECK(!plane.Split(err));
    BOOST_CHECK_EQUAL(err, "ARTIFACT");
    BOOST_REQUIRE(!plane.has_split());
    BOOST_REQUIRE(plane.pieces().empty());

    BOOST_REQUIRE(plane.Capture(err));
    BOOST_REQUIRE(plane.Split(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has_split());

    const std::vector<std::string>& pieces = plane.pieces();
    BOOST_REQUIRE(pieces.size() >= 2);
    std::string glued;
    for (std::size_t i = 0; i < pieces.size(); ++i) {
        if (i + 1 < pieces.size()) {
            BOOST_REQUIRE_EQUAL(pieces[i].size(), 32U);
        } else {
            BOOST_REQUIRE(pieces[i].size() >= 1);
            BOOST_REQUIRE(pieces[i].size() <= 32U);
        }
        glued += pieces[i];
    }
    BOOST_REQUIRE(glued == plane.captured());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(piece_layout_rejects_a_short_non_last_piece)
{
    std::string err = "prior";
    const std::vector<std::string> short_non_last{std::string(31, 'a'), std::string(31, 'b')};
    BOOST_CHECK(!modelnet::ArtifactPiecesFit(short_non_last, err));
    BOOST_CHECK_EQUAL(err, "SHORT");

    const std::vector<std::string> empty_last{std::string(32, 'a'), std::string()};
    BOOST_CHECK(!modelnet::ArtifactPiecesFit(empty_last, err));
    BOOST_CHECK_EQUAL(err, "SHORT");

    const std::vector<std::string> fitting{std::string(32, 'a'), std::string(31, 'b')};
    BOOST_REQUIRE(modelnet::ArtifactPiecesFit(fitting, err));
    BOOST_REQUIRE(err.empty());
}

BOOST_AUTO_TEST_CASE(join_round_trip_is_local_reassembly)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Capture(err));
    BOOST_REQUIRE(plane.Split(err));
    BOOST_REQUIRE(!plane.joined());
    BOOST_REQUIRE(plane.reassembly().empty());

    const std::vector<std::string>& pieces = plane.pieces();
    BOOST_REQUIRE(pieces.size() >= 2);
    for (std::size_t i = 0; i < pieces.size(); ++i) {
        BOOST_REQUIRE(plane.Offer(static_cast<int64_t>(i), pieces[i], err));
    }
    BOOST_REQUIRE(plane.Join(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.joined());
    BOOST_REQUIRE(plane.reassembly() == plane.captured());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);

    BOOST_REQUIRE(plane.Join(err));
    BOOST_REQUIRE(plane.joined());
    BOOST_REQUIRE(plane.reassembly() == plane.captured());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
