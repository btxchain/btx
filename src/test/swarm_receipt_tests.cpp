// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_receipt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_receipt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_field_stores_nothing)
{
    modelnet::SwarmReceiptBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.Accept("", "worker", "r1", "body", 1, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(!book.Accept("task", "", "r1", "body", 1, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(!book.Accept("task", "worker", "", "body", 1, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(!book.Accept("task", "worker", "r1", "", 1, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(!book.Accept("task", "worker", "r1", "body", 0, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(!book.Accept("task", "worker", "r1", "body", -1, true, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(book.Count(), 0);
    BOOST_CHECK(!book.Found("task", "worker", "r1", "body", 1));
}

BOOST_AUTO_TEST_CASE(first_accept_counts_one)
{
    modelnet::SwarmReceiptBook book;
    std::string err = "prior";
    BOOST_CHECK(book.Accept("task", "worker", "r1", "body-a", 1, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 1));
}

BOOST_AUTO_TEST_CASE(idempotent_repeat_including_disconnected)
{
    modelnet::SwarmReceiptBook book;
    std::string err;
    BOOST_REQUIRE(book.Accept("task", "worker", "r1", "body-a", 1, false, err));
    BOOST_CHECK(book.Accept("task", "worker", "r1", "body-a", 1, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK(book.Accept("task", "worker", "r1", "body-a", 1, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 1));
}

BOOST_AUTO_TEST_CASE(same_receipt_different_body_conflicts)
{
    modelnet::SwarmReceiptBook book;
    std::string err;
    BOOST_REQUIRE(book.Accept("task", "worker", "r1", "body-a", 1, false, err));
    BOOST_CHECK(!book.Accept("task", "worker", "r1", "body-b", 1, false, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 1));
    BOOST_CHECK(!book.Found("task", "worker", "r1", "body-b", 1));

    BOOST_CHECK(!book.Accept("task", "worker", "r1", "body-a", 2, true, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 1));
    BOOST_CHECK_EQUAL(book.Count(), 1);

    BOOST_CHECK(!book.Accept("task", "worker", "r1", "", 1, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 1));
}

BOOST_AUTO_TEST_CASE(different_receipt_same_generation_is_duplicate)
{
    modelnet::SwarmReceiptBook book;
    std::string err;
    BOOST_REQUIRE(book.Accept("task", "worker", "r1", "body-a", 2, false, err));
    BOOST_CHECK(!book.Accept("task", "worker", "r2", "body-b", 2, false, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 2));
    BOOST_CHECK(!book.Found("task", "worker", "r2", "body-b", 2));

    BOOST_CHECK(!book.Accept("task", "worker", "r3", "body-c", 2, true, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 2));

    BOOST_CHECK(!book.Accept("task", "worker", "r4", "body-d", 1, false, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK(book.Found("task", "worker", "r1", "body-a", 2));
}

BOOST_AUTO_TEST_CASE(higher_generation_replaces_and_count_stays)
{
    modelnet::SwarmReceiptBook book;
    std::string err;
    BOOST_REQUIRE(book.Accept("task", "worker", "r1", "body-a", 1, false, err));
    BOOST_CHECK(book.Accept("task", "worker", "r2", "body-b", 2, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK(book.Found("task", "worker", "r2", "body-b", 2));
    BOOST_CHECK(!book.Found("task", "worker", "r1", "body-a", 1));
    BOOST_CHECK(book.Accept("task", "worker", "r2", "body-b", 2, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
}

BOOST_AUTO_TEST_CASE(second_task_is_a_separate_row)
{
    modelnet::SwarmReceiptBook book;
    std::string err;
    BOOST_REQUIRE(book.Accept("task-a", "worker", "r1", "body-a", 1, false, err));
    BOOST_CHECK(book.Accept("task-b", "worker", "r2", "body-b", 1, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 2);
    BOOST_CHECK(book.Found("task-a", "worker", "r1", "body-a", 1));
    BOOST_CHECK(book.Found("task-b", "worker", "r2", "body-b", 1));
}

BOOST_AUTO_TEST_SUITE_END()
