// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quota.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_quota_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_pin_survives_a_store_that_would_pass_the_cap)
{
    modelnet::SwarmQuotaBook book;
    std::string err;

    BOOST_CHECK(!book.Open(0, err));
    BOOST_CHECK_EQUAL(err, "QUOTA");
    BOOST_CHECK_EQUAL(book.Used(), 0);
    BOOST_CHECK_EQUAL(book.Pinned(), 0);

    BOOST_REQUIRE(book.Open(100, err));
    BOOST_CHECK(!book.Open(100, err));
    BOOST_CHECK_EQUAL(err, "REOPEN");
    BOOST_CHECK_EQUAL(book.Used(), 0);

    BOOST_CHECK(!book.Pin("", 60, err));
    BOOST_CHECK_EQUAL(err, "PIN");
    BOOST_CHECK(!book.Pin("held", 0, err));
    BOOST_CHECK_EQUAL(err, "PIN");
    BOOST_CHECK_EQUAL(book.Used(), 0);
    BOOST_CHECK_EQUAL(book.Pinned(), 0);

    BOOST_REQUIRE(book.Pin("held", 60, err));
    BOOST_CHECK_EQUAL(book.Used(), 60);
    BOOST_CHECK_EQUAL(book.Pinned(), 1);

    BOOST_CHECK(!book.Store("extra", 50, err));
    BOOST_CHECK_EQUAL(err, "QUOTA");
    BOOST_CHECK_EQUAL(book.Used(), 60);
    BOOST_CHECK_EQUAL(book.Pinned(), 1);

    BOOST_REQUIRE(book.Pin("held", 60, err));
    BOOST_CHECK_EQUAL(book.Used(), 60);
    BOOST_CHECK_EQUAL(book.Pinned(), 1);

    BOOST_CHECK(!book.Pin("held", 61, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(book.Used(), 60);
    BOOST_CHECK_EQUAL(book.Pinned(), 1);

    BOOST_REQUIRE(book.Store("rest", 40, err));
    BOOST_CHECK_EQUAL(book.Used(), 100);
    BOOST_CHECK_EQUAL(book.Pinned(), 1);

    BOOST_REQUIRE(book.Store("held", 60, err));
    BOOST_CHECK_EQUAL(book.Used(), 100);
    BOOST_CHECK_EQUAL(book.Pinned(), 1);

    BOOST_CHECK(!book.Store("more", 1, err));
    BOOST_CHECK_EQUAL(err, "QUOTA");
    BOOST_CHECK_EQUAL(book.Used(), 100);
    BOOST_CHECK_EQUAL(book.Pinned(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
