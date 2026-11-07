// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/artifact.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void RequireSplit(modelnet::SwarmArtifact& plane, std::string& err)
{
    BOOST_REQUIRE(plane.Capture(err));
    BOOST_REQUIRE(plane.Split(err));
    BOOST_REQUIRE(plane.pieces().size() >= 2);
    BOOST_REQUIRE_EQUAL(plane.pieces().front().size(), 32U);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_artifact_offer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(negative_index_is_not_stored)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Offer(-1, "piece", err));
    BOOST_CHECK_EQUAL(err, "INDEX");
    BOOST_REQUIRE(plane.offered(-1) == nullptr);
    BOOST_REQUIRE_EQUAL(plane.offer_count(), 0U);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(same_bytes_are_replay)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";
    RequireSplit(plane, err);

    const std::string first = plane.pieces()[0];
    BOOST_REQUIRE(plane.Offer(0, first, err));
    BOOST_CHECK(!plane.Offer(0, first, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.offered(0) != nullptr);
    BOOST_REQUIRE(*plane.offered(0) == first);
    BOOST_REQUIRE_EQUAL(plane.offer_count(), 1U);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(conflicting_piece_keeps_the_first)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";
    RequireSplit(plane, err);

    const std::vector<std::string> pieces = plane.pieces();
    std::string bad = pieces[0];
    bad[0] = static_cast<char>(static_cast<unsigned char>(bad[0]) ^ 0x01);
    BOOST_REQUIRE(bad != pieces[0]);
    BOOST_REQUIRE_EQUAL(bad.size(), 32U);

    BOOST_REQUIRE(plane.Offer(0, bad, err));
    BOOST_CHECK(!plane.Offer(0, pieces[0], err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE(plane.offered(0) != nullptr);
    BOOST_REQUIRE(*plane.offered(0) == bad);

    for (std::size_t i = 1; i < pieces.size(); ++i) {
        BOOST_REQUIRE(plane.Offer(static_cast<int64_t>(i), pieces[i], err));
    }
    BOOST_CHECK(!plane.Join(err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_REQUIRE(!plane.joined());
    BOOST_REQUIRE(plane.reassembly().empty());
    BOOST_REQUIRE(*plane.offered(0) == bad);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
}

BOOST_AUTO_TEST_CASE(gap_is_allowed_until_join)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";
    RequireSplit(plane, err);

    const std::vector<std::string> pieces = plane.pieces();
    BOOST_REQUIRE(pieces.size() >= 3);

    // Last index first: a hole at index 1 is still accepted here.
    BOOST_REQUIRE(plane.Offer(static_cast<int64_t>(pieces.size() - 1), pieces.back(), err));
    BOOST_REQUIRE(plane.Offer(0, pieces[0], err));
    for (std::size_t i = 2; i + 1 < pieces.size(); ++i) {
        BOOST_REQUIRE(plane.Offer(static_cast<int64_t>(i), pieces[i], err));
    }
    BOOST_REQUIRE(plane.offered(1) == nullptr);

    BOOST_CHECK(!plane.Join(err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_REQUIRE(!plane.joined());
    BOOST_REQUIRE(plane.reassembly().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());

    BOOST_REQUIRE(plane.Offer(1, pieces[1], err));
    BOOST_REQUIRE(plane.Join(err));
    BOOST_REQUIRE(plane.joined());
    BOOST_REQUIRE(plane.reassembly() == plane.captured());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(short_offered_piece_does_not_join)
{
    modelnet::SwarmArtifact plane;
    std::string err = "prior";
    RequireSplit(plane, err);

    const std::vector<std::string> pieces = plane.pieces();
    BOOST_REQUIRE(pieces[0].size() == 32);
    const std::string short_piece = pieces[0].substr(0, 31);
    BOOST_REQUIRE(plane.Offer(0, short_piece, err));
    for (std::size_t i = 1; i < pieces.size(); ++i) {
        BOOST_REQUIRE(plane.Offer(static_cast<int64_t>(i), pieces[i], err));
    }
    BOOST_CHECK(!plane.Join(err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_REQUIRE(!plane.joined());
    BOOST_REQUIRE(plane.reassembly().empty());
    BOOST_REQUIRE(plane.offered(0) != nullptr);
    BOOST_REQUIRE(*plane.offered(0) == short_piece);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
