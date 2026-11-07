// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/collatbook.h>
#include <modelnet/swarm_collatbook/same.h>
#include <modelnet/swarm_paymesh.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_collatbook_same_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_pool_returns_the_helper_error)
{
    modelnet::SwarmCollateralBook same;
    std::string err = "prior";
    BOOST_REQUIRE(modelnet::SwarmCollatNoteFirst(same, "pool-a", "txid:0", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(same.FirstPool("txid:0"), "pool-a");

    err = "prior";
    BOOST_CHECK(!modelnet::SwarmCollatRefuseSecond(same, "pool-a", "pool-b", "txid:0", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(same.FirstPool("txid:0"), "pool-a");
}

BOOST_AUTO_TEST_CASE(helper_clears_err_still_refuses)
{
    modelnet::SwarmCollateralBook same;
    std::string err = "prior";
    BOOST_REQUIRE(modelnet::SwarmCollatNoteFirst(same, "pool-a", "txid:0", err));

    // The helper accepts the same pool twice and clears err. A second
    // reservation is still refused, and the error is COLLATERAL_REUSE.
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmCollatRefuseSecond(same, "pool-a", "pool-a", "txid:0", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(same.FirstPool("txid:0"), "pool-a");
}

BOOST_AUTO_TEST_CASE(book_keeps_the_first_pool_in_the_helper)
{
    modelnet::SwarmCollatBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("pool-a", "txid:0", "escrow", err));
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");

    err = "prior";
    BOOST_CHECK(!book.Reserve("pool-b", "txid:0", "collateral", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(book.first_pool("txid:0"), "pool-a");
    BOOST_CHECK_EQUAL(book.rows(), 1);
    BOOST_CHECK_EQUAL(book.bucket("txid:0"), "escrow");
    BOOST_CHECK_EQUAL(book.earned(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
