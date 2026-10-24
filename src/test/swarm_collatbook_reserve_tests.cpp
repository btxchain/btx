// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/bucket.h>
#include <modelnet/swarm_collatbook/collatbook.h>
#include <modelnet/swarm_collatbook/table.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_collatbook_reserve_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_or_outpoint_is_collateral)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.Reserve("", "txid:0", "escrow", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK_EQUAL(book.rows(), 0);
    BOOST_CHECK(!book.held("txid:0"));
    BOOST_CHECK(book.first_pool("txid:0").empty());
    BOOST_CHECK_EQUAL(book.earned(), 0);

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "", "collateral", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK_EQUAL(book.rows(), 0);
    BOOST_CHECK(!book.held(""));
    BOOST_CHECK(book.winner("").empty());

    err = "prior";
    BOOST_CHECK(!book.Reserve("", "", "escrow", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK_EQUAL(book.rows(), 0);

    err = "prior";
    BOOST_CHECK(!book.Reserve("", "txid:0", "nope", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK_EQUAL(book.rows(), 0);

    err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
}

BOOST_AUTO_TEST_CASE(other_bucket_stores_nothing)
{
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmCollatAcceptBucket("", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmCollatAcceptBucket("Escrow", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmCollatAcceptBucket("both", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    err = "prior";
    BOOST_REQUIRE(modelnet::SwarmCollatAcceptBucket("escrow", err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_REQUIRE(modelnet::SwarmCollatAcceptBucket("collateral", err));
    BOOST_CHECK(err.empty());

    modelnet::SwarmCollatBook book;
    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    BOOST_CHECK_EQUAL(book.rows(), 0);
    BOOST_CHECK(!book.held("txid:0"));
    BOOST_CHECK(book.first_pool("txid:0").empty());

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "escrow ", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    BOOST_CHECK_EQUAL(book.rows(), 0);

    err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "collateral");

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "ESCROW", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "collateral");
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
}

BOOST_AUTO_TEST_CASE(collateral_then_escrow_on_one_outpoint_is_both)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "collateral", err));

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_CHECK_EQUAL(err, "BOTH");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "collateral");
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(other_outpoints_are_separate_rows)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:1", "collateral", err));
    BOOST_REQUIRE(book.Reserve("pool-b", "txid:2", "escrow", err));
    BOOST_CHECK_EQUAL(book.rows(), 3);
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.bucket("txid:1"), "collateral");
    BOOST_CHECK_EQUAL(book.winner("txid:2"), "pool-b");
    BOOST_CHECK_EQUAL(book.first_pool("txid:1"), "pool-a");
    BOOST_CHECK_EQUAL(book.first_pool("txid:2"), "pool-b");
    BOOST_CHECK_EQUAL(book.earned(), 0);

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-b", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(book.rows(), 3);
    BOOST_CHECK_EQUAL(book.winner("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");
}

BOOST_AUTO_TEST_CASE(table_insert_does_not_replace_a_row)
{
    modelnet::SwarmCollatTable table;
    BOOST_CHECK(!table.Insert("", "txid:0", "escrow"));
    BOOST_CHECK(!table.Insert("pool-a", "", "escrow"));
    BOOST_CHECK(!table.Insert("pool-a", "txid:0", ""));
    BOOST_CHECK_EQUAL(table.rows(), 0);

    BOOST_REQUIRE(table.Insert("pool-a", "txid:0", "escrow"));
    BOOST_CHECK(table.held("txid:0"));
    BOOST_CHECK(!table.Insert("pool-b", "txid:0", "collateral"));
    BOOST_CHECK(!table.Insert("pool-a", "txid:0", "collateral"));
    BOOST_CHECK_EQUAL(table.rows(), 1);

    std::string pool = "prior";
    std::string bucket = "prior";
    BOOST_REQUIRE(table.Find("txid:0", pool, bucket));
    BOOST_CHECK_EQUAL(pool, "pool-a");
    BOOST_CHECK_EQUAL(bucket, "escrow");

    pool = "prior";
    bucket = "prior";
    BOOST_CHECK(!table.Find("txid:1", pool, bucket));
    BOOST_CHECK_EQUAL(pool, "prior");
    BOOST_CHECK_EQUAL(bucket, "prior");
}

BOOST_AUTO_TEST_SUITE_END()
