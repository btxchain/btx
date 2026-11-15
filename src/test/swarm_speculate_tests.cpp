// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_speculate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_speculate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_stores_a_branch_under_the_primary)
{
    modelnet::SwarmSpeculate spec;
    std::string err = "prior";
    BOOST_CHECK(!spec.Open("", "branch-a", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(!spec.Open("primary-a", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(!spec.Open("", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");

    BOOST_REQUIRE(spec.Open("primary-a", "branch-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!spec.Open("primary-a", "branch-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!spec.Open("primary-b", "branch-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_REQUIRE(spec.Open("primary-a", "branch-b", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(matching_finished_branch_is_reused)
{
    modelnet::SwarmSpeculate spec;
    std::string err = "prior";
    BOOST_REQUIRE(spec.Open("primary-a", "branch-a", err));
    BOOST_REQUIRE(spec.Finish("branch-a", "hash-1", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(spec.Finish("branch-a", "hash-1", err));
    BOOST_CHECK(err.empty());

    std::string reused = "prior";
    BOOST_REQUIRE(spec.Reuse("primary-a", "hash-1", reused, err));
    BOOST_CHECK_EQUAL(reused, "branch-a");
    BOOST_CHECK(err.empty());

    reused = "prior";
    BOOST_REQUIRE(spec.Reuse("primary-a", "hash-1", reused, err));
    BOOST_CHECK_EQUAL(reused, "branch-a");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(hash_mismatch_is_no_reuse)
{
    modelnet::SwarmSpeculate spec;
    std::string err = "prior";
    BOOST_REQUIRE(spec.Open("primary-a", "branch-a", err));
    BOOST_REQUIRE(spec.Finish("branch-a", "hash-1", err));
    BOOST_REQUIRE(spec.Open("primary-a", "branch-open", err));

    std::string reused = "prior";
    BOOST_CHECK(!spec.Reuse("primary-a", "hash-2", reused, err));
    BOOST_CHECK(reused.empty());
    BOOST_CHECK_EQUAL(err, "NO_REUSE");

    reused = "prior";
    BOOST_CHECK(!spec.Reuse("primary-b", "hash-1", reused, err));
    BOOST_CHECK(reused.empty());
    BOOST_CHECK_EQUAL(err, "NO_REUSE");

    reused = "prior";
    BOOST_CHECK(!spec.Reuse("primary-a", "", reused, err));
    BOOST_CHECK(reused.empty());
    BOOST_CHECK_EQUAL(err, "NO_REUSE");
}

BOOST_AUTO_TEST_CASE(conflicting_finish_keeps_the_first_hash)
{
    modelnet::SwarmSpeculate spec;
    std::string err = "prior";
    BOOST_CHECK(!spec.Finish("branch-missing", "hash-1", err));
    BOOST_CHECK_EQUAL(err, "TASK");

    BOOST_REQUIRE(spec.Open("primary-a", "branch-a", err));
    BOOST_CHECK(!spec.Finish("branch-a", "", err));
    BOOST_CHECK_EQUAL(err, "HASH");

    BOOST_REQUIRE(spec.Finish("branch-a", "hash-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!spec.Finish("branch-a", "hash-2", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");

    BOOST_REQUIRE(spec.Finish("branch-a", "hash-1", err));
    BOOST_CHECK(err.empty());

    std::string reused;
    BOOST_REQUIRE(spec.Reuse("primary-a", "hash-1", reused, err));
    BOOST_CHECK_EQUAL(reused, "branch-a");
    BOOST_CHECK(!spec.Reuse("primary-a", "hash-2", reused, err));
    BOOST_CHECK(reused.empty());
    BOOST_CHECK_EQUAL(err, "NO_REUSE");
}

BOOST_AUTO_TEST_SUITE_END()
