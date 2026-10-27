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

BOOST_FIXTURE_TEST_SUITE(swarm_dedup_alone_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(the_only_holder_is_alone)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "ALONE");
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
}

BOOST_AUTO_TEST_CASE(alone_does_not_copy_or_drop_the_holder)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));

    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "ALONE");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.digest_bound("piece-1"));
    const std::vector<std::string> holders = book.holders("piece-1");
    BOOST_CHECK_EQUAL(holders.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(holders.at(0), "peer-a");
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(a_different_requester_is_held)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Pull("peer-b", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(!book.announced("peer-b", "piece-1"));
}

BOOST_AUTO_TEST_CASE(a_second_holder_changes_alone_to_held)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "ALONE");

    BOOST_CHECK(book.Announce("peer-b", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));
    const std::vector<std::string> holders = book.holders("piece-1");
    const std::vector<std::string> expect{"peer-a", "peer-b"};
    BOOST_CHECK(holders == expect);
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(dropping_the_other_holder_returns_to_alone)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Announce("peer-b", "piece-1", false, err));
    BOOST_CHECK(book.Drop("peer-b", "piece-1", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "ALONE");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(!book.announced("peer-b", "piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_piece_is_not_alone)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_requester_is_not_alone)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Pull("", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(an_unknown_piece_is_missing)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-2", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.holders("piece-2").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_SUITE_END()
