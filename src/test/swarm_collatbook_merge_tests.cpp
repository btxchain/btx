// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/collatbook.h>
#include <modelnet/swarm_collatbook/merge.h>
#include <modelnet/swarm_collatbook/quiet.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_collatbook_merge_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(merge_before_reserve_moves_nothing)
{
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmCollatMerge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK(!modelnet::SwarmCollatBroadcast());
    BOOST_CHECK_EQUAL(modelnet::SwarmCollatBytesMoved(), 0);
    BOOST_CHECK_EQUAL(modelnet::SwarmCollatEarned(), 0);

    modelnet::SwarmCollatBook book;
    err = "prior";
    BOOST_CHECK(!book.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(book.rows(), 0);
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(refused_reserve_does_not_earn_or_broadcast)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-b", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-a", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "BOTH");
    err = "prior";
    BOOST_CHECK(!book.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");

    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.earned(), 0);
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
