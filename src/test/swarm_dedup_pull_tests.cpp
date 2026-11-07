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

BOOST_FIXTURE_TEST_SUITE(swarm_dedup_pull_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_is_piece_even_when_the_requester_is_empty)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Pull("", "", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    ExpectStill(book);

    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_requester_is_peer)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Pull("", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(no_holder_is_missing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(!book.announced("peer-a", "piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(a_digest_without_a_holder_is_missing)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(book.digest_bound("piece-1"));
    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(book.digest_bound("piece-1"));
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(another_peer_is_held_and_moves_no_bytes)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Pull("peer-b", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(!book.announced("peer-b", "piece-1"));
    BOOST_CHECK_EQUAL(book.holders("piece-1").size(), static_cast<std::size_t>(1));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(a_second_holder_still_returns_held_with_no_bytes_moved)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_CHECK(book.Announce("peer-b", "piece-1", false, err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));

    err = "prior";
    BOOST_CHECK(!book.Pull("peer-b", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));

    err = "prior";
    BOOST_CHECK(!book.Pull("peer-c", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));

    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.announced("peer-b", "piece-1"));
    BOOST_CHECK(!book.announced("peer-c", "piece-1"));
    const std::vector<std::string> holders = book.holders("piece-1");
    const std::vector<std::string> expect{"peer-a", "peer-b"};
    BOOST_CHECK(holders == expect);
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
}

BOOST_AUTO_TEST_CASE(pull_does_not_change_holders_or_the_digest)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Announce("peer-b", "piece-1", false, err));
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!book.Pull("peer-c", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(book.digest_bound("piece-1"));
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.announced("peer-b", "piece-1"));
    BOOST_CHECK_EQUAL(book.holders("piece-1").size(), static_cast<std::size_t>(2));
    ExpectStill(book);
}

BOOST_AUTO_TEST_SUITE_END()
