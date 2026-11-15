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

BOOST_FIXTURE_TEST_SUITE(swarm_dedup_drop_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(an_unknown_pair_is_missing_and_deletes_nothing)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(!book.Drop("peer-b", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(!book.announced("peer-b", "piece-1"));
    BOOST_CHECK_EQUAL(book.holders("piece-1").size(), static_cast<std::size_t>(1));
    ExpectStill(book);

    err = "prior";
    BOOST_CHECK(!book.Drop("peer-a", "piece-2", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.holders("piece-2").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(an_empty_pair_is_missing)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(!book.Drop("", "", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    err = "prior";
    BOOST_CHECK(!book.Drop("peer-a", "", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    err = "prior";
    BOOST_CHECK(!book.Drop("", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(a_known_pair_removes_that_holder)
{
    modelnet::SwarmPieceDedup book;
    std::string err = "prior";
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_CHECK(book.Drop("peer-a", "piece-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(other_holders_of_the_same_piece_stay)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-b", "piece-1", false, err));
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Announce("peer-c", "piece-1", false, err));
    err = "prior";
    BOOST_CHECK(book.Drop("peer-b", "piece-1", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!book.announced("peer-b", "piece-1"));
    BOOST_CHECK(book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.announced("peer-c", "piece-1"));
    const std::vector<std::string> holders = book.holders("piece-1");
    const std::vector<std::string> expect{"peer-a", "peer-c"};
    BOOST_CHECK(holders == expect);
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(another_piece_for_the_same_peer_stays)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Announce("peer-a", "piece-2", false, err));
    BOOST_CHECK(book.Drop("peer-a", "piece-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.announced("peer-a", "piece-2"));
    BOOST_CHECK(book.holders("piece-1").empty());
    BOOST_CHECK_EQUAL(book.holders("piece-2").at(0), "peer-a");
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(a_second_drop_of_the_same_pair_is_missing)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Drop("peer-a", "piece-1", err));
    err = "prior";
    BOOST_CHECK(!book.Drop("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(book.holders("piece-1").empty());
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(drop_does_not_clear_the_digest)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Digest("piece-1", "piece-1", err));
    BOOST_CHECK(book.Drop("peer-a", "piece-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!book.announced("peer-a", "piece-1"));
    BOOST_CHECK(book.digest_bound("piece-1"));
    ExpectStill(book);
}

BOOST_AUTO_TEST_CASE(the_last_holder_drop_makes_a_later_pull_missing)
{
    modelnet::SwarmPieceDedup book;
    std::string err;
    BOOST_CHECK(book.Announce("peer-a", "piece-1", false, err));
    BOOST_CHECK(book.Drop("peer-a", "piece-1", err));
    err = "prior";
    BOOST_CHECK(!book.Pull("peer-a", "piece-1", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
