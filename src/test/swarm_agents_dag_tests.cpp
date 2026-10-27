// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

static void ExpectReady(const modelnet::SwarmAgentPlane& plane, const std::vector<std::string>& want)
{
    const std::vector<std::string> got = plane.Ready();
    BOOST_REQUIRE_EQUAL(got.size(), want.size());
    for (std::size_t i = 0; i < want.size(); ++i) {
        BOOST_REQUIRE_EQUAL(got[i], want[i]);
    }
}

static bool Contains(const std::vector<std::string>& ids, const std::string& id)
{
    for (const std::string& cur : ids) {
        if (cur == id) {
            return true;
        }
    }
    return false;
}

BOOST_FIXTURE_TEST_SUITE(swarm_agents_dag_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_unknown_dep_self_dep_and_duplicate)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";

    BOOST_CHECK(!plane.Add("", {}, err));
    BOOST_CHECK_EQUAL(err, "TASK");
    ExpectReady(plane, {});

    err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_CHECK(!plane.Add("b", {"missing"}, err));
    BOOST_CHECK_EQUAL(err, "DEP");
    ExpectReady(plane, {"a"});
    BOOST_CHECK(plane.CommittedHash("b").empty());

    err = "prior";
    BOOST_CHECK(!plane.Add("c", {"c"}, err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    ExpectReady(plane, {"a"});

    err = "prior";
    BOOST_CHECK(!plane.Add("a", {}, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    ExpectReady(plane, {"a"});
}

BOOST_AUTO_TEST_CASE(commit_same_hash_is_idempotent_and_different_hash_keeps_the_first)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE(plane.Commit("a", "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");
    ExpectReady(plane, {});

    err = "prior";
    BOOST_REQUIRE(plane.Commit("a", "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");

    err = "prior";
    BOOST_CHECK(!plane.Commit("a", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");

    err = "prior";
    BOOST_CHECK(!plane.Commit("a", "", err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");
}

BOOST_AUTO_TEST_CASE(ready_waits_for_every_dependency)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE(plane.Add("b", {"a"}, err));
    BOOST_REQUIRE(plane.Add("c", {"a"}, err));
    BOOST_REQUIRE(plane.Add("d", {"b", "c"}, err));
    BOOST_REQUIRE(err.empty());
    ExpectReady(plane, {"a"});

    BOOST_REQUIRE(plane.Commit("a", "hash-a", err));
    ExpectReady(plane, {"b", "c"});

    err = "prior";
    BOOST_CHECK(!plane.Commit("d", "hash-d", err));
    BOOST_CHECK_EQUAL(err, "NOT_READY");
    BOOST_CHECK(plane.CommittedHash("d").empty());

    BOOST_REQUIRE(plane.Commit("b", "hash-b", err));
    ExpectReady(plane, {"c"});
    BOOST_REQUIRE(plane.Commit("c", "hash-c", err));
    ExpectReady(plane, {"d"});
    BOOST_REQUIRE(plane.Commit("d", "hash-d", err));
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("d"), "hash-d");
    ExpectReady(plane, {});
}

BOOST_AUTO_TEST_CASE(cancel_middle_of_three_keeps_the_last_unready)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE(plane.Add("b", {"a"}, err));
    BOOST_REQUIRE(plane.Add("c", {"b"}, err));
    ExpectReady(plane, {"a"});

    BOOST_REQUIRE(plane.Commit("a", "hash-a", err));
    ExpectReady(plane, {"b"});

    BOOST_REQUIRE(plane.Cancel("b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!Contains(plane.Ready(), "b"));
    BOOST_REQUIRE(!Contains(plane.Ready(), "c"));
    ExpectReady(plane, {});

    err = "prior";
    BOOST_CHECK(!plane.Commit("b", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CANCELLED");
    BOOST_CHECK(plane.CommittedHash("b").empty());

    err = "prior";
    BOOST_CHECK(!plane.Commit("c", "hash-c", err));
    BOOST_CHECK_EQUAL(err, "NOT_READY");
    BOOST_CHECK(plane.CommittedHash("c").empty());
    BOOST_REQUIRE(!Contains(plane.Ready(), "c"));
    ExpectReady(plane, {});

    err = "prior";
    BOOST_CHECK(!plane.Cancel("a", err));
    BOOST_CHECK_EQUAL(err, "COMMITTED");
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");
}

BOOST_AUTO_TEST_SUITE_END()
