// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/balances.h>
#include <modelnet/swarm_paystage/paystage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paystage_balances_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_bucket_and_atoms_add_nothing)
{
    modelnet::SwarmPayBalances book;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(book.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(book.Balance("fees"), 0);
    BOOST_CHECK_EQUAL(book.Balance("profit"), -1);

    BOOST_CHECK(!book.Credit("profit", 5, "memo-1", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    BOOST_CHECK_EQUAL(book.Balance("profit"), -1);
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 0);
    BOOST_CHECK(!book.HasMemo("memo-1"));

    err = "prior";
    BOOST_CHECK(!book.Credit("", 5, "memo-1", err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    BOOST_CHECK(!book.HasMemo("memo-1"));

    err = "prior";
    BOOST_CHECK(!book.Credit("escrow", 0, "memo-1", err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 0);

    err = "prior";
    BOOST_CHECK(!book.Credit("escrow", -4, "memo-1", err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 0);
    BOOST_CHECK(!book.HasMemo("memo-1"));

    err = "prior";
    BOOST_CHECK(!book.Credit("fees", 2, "", err));
    BOOST_CHECK_EQUAL(err, "MEMO");
    BOOST_CHECK_EQUAL(book.Balance("fees"), 0);
}

BOOST_AUTO_TEST_CASE(same_memo_is_not_added_to_escrow_and_collateral)
{
    modelnet::SwarmPayBalances book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Credit("escrow", 7, "same", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.HasMemo("same"));
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 7);
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 0);

    err = "prior";
    BOOST_CHECK(!book.Credit("collateral", 7, "same", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 7);
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(book.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(book.Balance("fees"), 0);

    err = "prior";
    BOOST_CHECK(!book.Credit("escrow", 1, "same", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 7);

    err = "prior";
    BOOST_REQUIRE(book.Credit("collateral", 2, "other", err));
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 2);
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 7);
}

BOOST_AUTO_TEST_CASE(overflow_leaves_the_bucket)
{
    modelnet::SwarmPayBalances book;
    std::string err = "prior";
    const int64_t almost = std::numeric_limits<int64_t>::max() - 5;
    BOOST_REQUIRE(book.Credit("fees", almost, "fee-a", err));
    BOOST_CHECK_EQUAL(book.Balance("fees"), almost);
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 0);

    err = "prior";
    BOOST_REQUIRE(book.Credit("fees", 5, "fee-b", err));
    BOOST_CHECK_EQUAL(book.Balance("fees"), std::numeric_limits<int64_t>::max());

    err = "prior";
    BOOST_CHECK(!book.Credit("fees", 1, "fee-c", err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(book.Balance("fees"), std::numeric_limits<int64_t>::max());
    BOOST_CHECK(!book.HasMemo("fee-c"));

    err = "prior";
    BOOST_REQUIRE(book.Credit("escrow", 1, "escrow-ok", err));
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 1);
    BOOST_CHECK_EQUAL(book.Balance("fees"), std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_CASE(merge_moves_nothing)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_REQUIRE(stage.Credit("escrow", 10, "e", err));
    BOOST_REQUIRE(stage.Credit("collateral", 11, "c", err));
    BOOST_REQUIRE(stage.Credit("earned", 12, "n", err));
    BOOST_REQUIRE(stage.Credit("fees", 13, "f", err));

    err = "prior";
    BOOST_CHECK(!stage.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 10);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 11);
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 12);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 13);

    err = "prior";
    BOOST_CHECK(!stage.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 10);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 11);
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 12);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 13);
}

BOOST_AUTO_TEST_SUITE_END()
