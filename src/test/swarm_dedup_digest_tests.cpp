// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/swarm_dedup.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectStill(const modelnet::SwarmPieceDedup& book)
{
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_dedup_digest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_is_piece_and_stores_nothing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Digest("", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!book.digest_bound(""));
    BOOST_CHECK(!book.digest_bound("piece-1"));
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_digest_is_digest_and_stores_nothing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Digest("piece-1", "", err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK(!book.digest_bound("piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_piece_wins_when_the_digest_is_also_empty)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Digest("", "", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!book.digest_bound(""));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(mismatched_digest_is_conflict_and_stores_nothing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Digest("piece-1", "piece-2", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(!book.digest_bound("piece-1"));
    BOOST_CHECK(!book.digest_bound("piece-2"));
    BOOST_CHECK(book.holders("piece-1").empty());
    BOOST_CHECK(book.holders("piece-2").empty());
    BOOST_CHECK(!book.announced("peer-a", "piece-1"));
    ExpectStill(book);

    err = "prior";
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.digest_bound("piece-1"));
    BOOST_CHECK(!book.digest_bound("piece-2"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(equal_digest_binds_once)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.digest_bound("piece-1"));
    BOOST_CHECK(!book.digest_bound("piece-2"));
    BOOST_CHECK(!book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(second_equal_binding_is_replay)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(book.digest_bound("piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(mismatch_after_a_bind_is_conflict_and_keeps_the_first)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!book.Digest("piece-1", "other-id", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(book.digest_bound("piece-1"));
    BOOST_CHECK(!book.digest_bound("other-id"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(a_binding_does_not_announce_a_holder)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-9", false, err));
    err = "prior";
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.digest_bound("piece-1"));
    BOOST_CHECK(!book.digest_bound("piece-9"));
    BOOST_CHECK(book.holders("piece-1").empty());
    const std::vector<std::string> holders = book.holders("piece-9");
    BOOST_CHECK_EQUAL(holders.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(holders.at(0), "peer-a");
    ExpectStill(book);
}

BOOST_AUTO_TEST_SUITE_END()
