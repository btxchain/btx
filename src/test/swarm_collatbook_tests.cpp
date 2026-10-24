// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/collatbook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_collatbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(first_reserve_records_one_outpoint)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(book.rows(), 0);
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
    BOOST_CHECK(!book.held("txid:0"));

    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.held("txid:0"));
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
    BOOST_CHECK(!book.held("txid:1"));
}

BOOST_AUTO_TEST_CASE(second_pool_is_refused)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-b", "txid:0", "escrow", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK(book.held("txid:0"));
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
    BOOST_CHECK(!book.broadcast());

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-b", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-c", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");
}

BOOST_AUTO_TEST_CASE(same_pool_replay_does_not_add_a_row)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(book.rows(), 1);

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "collateral");
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(both_buckets_are_refused)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "BOTH");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
    BOOST_CHECK(!book.broadcast());

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
}

BOOST_AUTO_TEST_CASE(merge_is_refused)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:1", "collateral", err));
    BOOST_CHECK_EQUAL(book.rows(), 2);

    err = "prior";
    BOOST_CHECK(!book.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(book.rows(), 2);
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.winner("txid:1"), "pool-a");
    BOOST_CHECK_EQUAL(book.bucket("txid:1"), "collateral");
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);

    err = "prior";
    BOOST_CHECK(!book.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(book.rows(), 2);
    BOOST_CHECK_EQUAL(book.earned(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
