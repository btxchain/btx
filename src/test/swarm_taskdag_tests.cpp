// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_taskdag.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

static void ExpectReady(const modelnet::SwarmTaskDag& dag, const std::vector<std::string>& want)
{
    const std::vector<std::string> got = dag.Ready();
    BOOST_CHECK_EQUAL(got.size(), want.size());
    const std::size_t n = got.size() < want.size() ? got.size() : want.size();
    for (std::size_t i = 0; i < n; ++i) {
        BOOST_CHECK_EQUAL(got[i], want[i]);
    }
}

BOOST_FIXTURE_TEST_SUITE(swarm_taskdag_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(diamond_ready_only_after_both_parents_commit)
{
    modelnet::SwarmTaskDag dag;
    std::string err = "prior";
    BOOST_CHECK(dag.Add("a", {}, err));
    BOOST_CHECK(dag.Add("b", {"a"}, err));
    BOOST_CHECK(dag.Add("c", {"a"}, err));
    BOOST_CHECK(dag.Add("d", {"b", "c"}, err));
    BOOST_CHECK(err.empty());

    ExpectReady(dag, {"a"});

    BOOST_CHECK(dag.Commit("a", "hash-a", err));
    BOOST_CHECK(err.empty());
    ExpectReady(dag, {"b", "c"});

    BOOST_CHECK(dag.Commit("b", "hash-b", err));
    ExpectReady(dag, {"c"});

    BOOST_CHECK(dag.Commit("c", "hash-c", err));
    ExpectReady(dag, {"d"});
}

BOOST_AUTO_TEST_CASE(cycle_is_rejected)
{
    modelnet::SwarmTaskDag dag;
    std::string err = "prior";
    BOOST_CHECK(dag.Add("a", {}, err));
    BOOST_CHECK(!dag.Add("b", {"a", "b"}, err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    ExpectReady(dag, {"a"});
    err = "prior";
    BOOST_CHECK(!dag.Commit("b", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(same_hash_commits_twice)
{
    modelnet::SwarmTaskDag dag;
    std::string err = "prior";
    BOOST_CHECK(dag.Add("a", {}, err));
    BOOST_CHECK(dag.Commit("a", "hash-a", err));
    BOOST_CHECK(err.empty());
    ExpectReady(dag, {});
    err = "prior";
    BOOST_CHECK(dag.Commit("a", "hash-a", err));
    BOOST_CHECK(err.empty());
    ExpectReady(dag, {});
}

BOOST_AUTO_TEST_CASE(different_hash_is_conflict)
{
    modelnet::SwarmTaskDag dag;
    std::string err = "prior";
    BOOST_CHECK(dag.Add("a", {}, err));
    BOOST_CHECK(dag.Commit("a", "hash-a", err));
    err = "prior";
    BOOST_CHECK(!dag.Commit("a", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    err = "prior";
    BOOST_CHECK(dag.Commit("a", "hash-a", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(cancel_blocks_dependent)
{
    modelnet::SwarmTaskDag dag;
    std::string err = "prior";
    BOOST_CHECK(dag.Add("parent", {}, err));
    BOOST_CHECK(dag.Add("child", {"parent"}, err));
    BOOST_CHECK(dag.Cancel("parent", err));
    BOOST_CHECK(err.empty());
    ExpectReady(dag, {});
    err = "prior";
    BOOST_CHECK(!dag.Commit("child", "hash-child", err));
    BOOST_CHECK_EQUAL(err, "NOT_READY");
    err = "prior";
    BOOST_CHECK(!dag.Commit("parent", "hash-parent", err));
    BOOST_CHECK_EQUAL(err, "CANCELLED");
}

BOOST_AUTO_TEST_SUITE_END()
