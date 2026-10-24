// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_specbranch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_specbranch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_commit_is_speculative)
{
    modelnet::SwarmSpeculativeBook book;
    std::string err = "prior";

    BOOST_CHECK(!book.CommitPrimary("", "digest-a", err));
    BOOST_CHECK_EQUAL(err, "SPECULATIVE");
    BOOST_CHECK(book.Committed("").empty());

    BOOST_CHECK(!book.CommitPrimary("branch-1", "", err));
    BOOST_CHECK_EQUAL(err, "SPECULATIVE");
    BOOST_CHECK(book.Committed("branch-1").empty());

    BOOST_CHECK_EQUAL(book.Speculate("branch-1", "digest-a", err), "SPECULATIVE");
    BOOST_CHECK_EQUAL(err, "SPECULATIVE");
    BOOST_CHECK(book.Committed("branch-1").empty());
}

BOOST_AUTO_TEST_CASE(different_digest_is_replay)
{
    modelnet::SwarmSpeculativeBook book;
    std::string err = "prior";

    BOOST_REQUIRE(book.CommitPrimary("branch-1", "digest-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");

    BOOST_CHECK(!book.CommitPrimary("branch-1", "digest-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");

    BOOST_CHECK(book.CommitPrimary("branch-1", "digest-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");
}

BOOST_AUTO_TEST_CASE(matching_speculation_returns_match)
{
    modelnet::SwarmSpeculativeBook book;
    std::string err;

    BOOST_REQUIRE(book.CommitPrimary("branch-1", "digest-a", err));
    BOOST_CHECK_EQUAL(book.Speculate("branch-1", "", err), "SPECULATIVE");
    BOOST_CHECK_EQUAL(err, "SPECULATIVE");
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");

    BOOST_CHECK_EQUAL(book.Speculate("branch-1", "digest-a", err), "MATCH");
    BOOST_CHECK_EQUAL(err, "MATCH");
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");
}

BOOST_AUTO_TEST_CASE(conflicting_speculation_leaves_committed)
{
    modelnet::SwarmSpeculativeBook book;
    std::string err;

    BOOST_REQUIRE(book.CommitPrimary("branch-1", "digest-a", err));
    const std::string committed = book.Committed("branch-1");

    BOOST_CHECK_EQUAL(book.Speculate("branch-1", "digest-b", err), "CONFLICT");
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), committed);
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");

    BOOST_CHECK_EQUAL(book.Speculate("branch-1", "digest-a", err), "MATCH");
    BOOST_CHECK_EQUAL(err, "MATCH");
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");

    BOOST_CHECK(!book.CommitPrimary("branch-1", "digest-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Committed("branch-1"), "digest-a");
}

BOOST_AUTO_TEST_SUITE_END()
