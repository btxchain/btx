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

BOOST_FIXTURE_TEST_SUITE(swarm_dedup_announce_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_is_peer_and_stores_nothing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Announce("", "piece-1", false, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!book.announced("", "piece-1"));
    BOOST_CHECK(book.holders("piece-1").empty());
    BOOST_CHECK(!book.digest_bound("piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_piece_is_piece_and_stores_nothing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Announce("peer-a", "", false, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!book.announced("peer-a", ""));
    BOOST_CHECK(book.holders("").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_peer_wins_when_the_piece_is_also_empty)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Announce("", "", false, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!book.announced("", ""));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_peer_wins_over_private)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Announce("", "piece-1", true, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(empty_piece_wins_over_private)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Announce("peer-a", "", true, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!book.announced("peer-a", ""));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(private_data_stores_nothing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Announce("peer-a", "piece-1", true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);

    err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(private_announce_does_not_remove_an_existing_holder)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!book.Announce("peer-b", "piece-1", true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(!book.announced("peer-b", "piece-1"));
    const std::vector<std::string> holders = book.holders("piece-1");
    BOOST_CHECK_EQUAL(holders.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(holders.at(0), "peer-a");
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(private_repeat_of_a_public_hold_is_private_data)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Announce("peer-a", "piece-1", true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK_EQUAL(book.holders("piece-1").size(), static_cast<std::size_t>(1));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(first_announce_records_the_holder_without_a_body)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(!book.announced("peer-b", "piece-1"));
    BOOST_CHECK(!book.announced("peer-a", "piece-2"));
    BOOST_CHECK(!book.digest_bound("piece-1"));
    const std::vector<std::string> holders = book.holders("piece-1");
    BOOST_CHECK_EQUAL(holders.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(holders.at(0), "peer-a");
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(second_announce_of_the_same_pair_is_replay)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK_EQUAL(book.holders("piece-1").size(), static_cast<std::size_t>(1));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(a_different_peer_is_another_holder)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Announce("peer-b", "piece-1", false, err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.announced("peer-b", "piece-1"));
    const std::vector<std::string> holders = book.holders("piece-1");
    const std::vector<std::string> expect{"peer-a", "peer-b"};
    BOOST_CHECK(holders == expect);
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(the_same_peer_can_hold_a_second_piece)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-2", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.announced("peer-a", "piece-2"));
    BOOST_CHECK_EQUAL(book.holders("piece-1").at(0), "peer-a");
    BOOST_CHECK_EQUAL(book.holders("piece-2").at(0), "peer-a");
    ExpectStill(book);
}

BOOST_AUTO_TEST_SUITE_END()
