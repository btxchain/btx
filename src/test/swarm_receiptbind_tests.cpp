// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_receiptbind.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_receiptbind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_receipt_or_job_is_receipt)
{
    modelnet::SwarmReceiptBind bind;
    std::string err = "stale";

    BOOST_CHECK(!bind.Bind("", "job-a", 100, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(!bind.Has(""));
    BOOST_CHECK_EQUAL(bind.total(), 0);

    BOOST_CHECK(!bind.Bind("rcpt-a", "", 100, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(!bind.Has("rcpt-a"));
    BOOST_CHECK_EQUAL(bind.total(), 0);

    BOOST_CHECK(!bind.Bind("", "", 0, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(bind.total(), 0);
}

BOOST_AUTO_TEST_CASE(atoms_below_one_is_atoms)
{
    modelnet::SwarmReceiptBind bind;
    std::string err = "stale";

    BOOST_CHECK(!bind.Bind("rcpt-a", "job-a", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK(!bind.Has("rcpt-a"));
    BOOST_CHECK_EQUAL(bind.total(), 0);

    BOOST_CHECK(!bind.Bind("rcpt-a", "job-a", -5, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK(!bind.Has("rcpt-a"));
    BOOST_CHECK_EQUAL(bind.total(), 0);
}

BOOST_AUTO_TEST_CASE(bind_replay_and_second_receipt)
{
    modelnet::SwarmReceiptBind bind;
    std::string err = "stale";

    BOOST_CHECK(!bind.Has("rcpt-a"));
    BOOST_CHECK(!bind.Has("rcpt-b"));
    BOOST_CHECK_EQUAL(bind.total(), 0);

    BOOST_REQUIRE(bind.Bind("rcpt-a", "job-a", 100, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(bind.Has("rcpt-a"));
    BOOST_CHECK_EQUAL(bind.total(), 100);

    BOOST_CHECK(!bind.Bind("rcpt-a", "job-other", 150, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(bind.Has("rcpt-a"));
    BOOST_CHECK_EQUAL(bind.total(), 100);

    BOOST_REQUIRE(bind.Bind("rcpt-b", "job-b", 150, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(bind.Has("rcpt-a"));
    BOOST_CHECK(bind.Has("rcpt-b"));
    BOOST_CHECK_EQUAL(bind.total(), 250);
}

BOOST_AUTO_TEST_SUITE_END()
