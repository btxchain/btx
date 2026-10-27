// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_survivor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_survivor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_commit)
{
    modelnet::SwarmDurableLog log;
    std::string err = "prior";
    BOOST_CHECK(!log.Commit("", 1, "c-1", "body", err));
    BOOST_CHECK_EQUAL(err, "DURABLE");
    BOOST_CHECK_EQUAL(log.Count(), 0);

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-a", 1, "", "body", err));
    BOOST_CHECK_EQUAL(err, "DURABLE");
    BOOST_CHECK_EQUAL(log.Count(), 0);

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-a", 1, "c-1", "", err));
    BOOST_CHECK_EQUAL(err, "DURABLE");
    BOOST_CHECK_EQUAL(log.Count(), 0);

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-a", 0, "c-1", "body", err));
    BOOST_CHECK_EQUAL(err, "DURABLE");
    BOOST_CHECK_EQUAL(log.Count(), 0);

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-a", -1, "c-1", "body", err));
    BOOST_CHECK_EQUAL(err, "DURABLE");
    BOOST_CHECK_EQUAL(log.Count(), 0);
}

BOOST_AUTO_TEST_CASE(stale_lower_epoch_commits_nothing)
{
    modelnet::SwarmDurableLog log;
    std::string err = "prior";
    BOOST_CHECK(log.Commit("coord-a", 2, "c-1", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(log.Count(), 1);

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-b", 1, "c-2", "body-b", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(log.Count(), 1);

    std::vector<std::string> ids{"leftover"};
    bool continues = false;
    err = "prior";
    BOOST_CHECK(log.Read("coord-a", 2, ids, continues, err));
    BOOST_CHECK(continues);
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE_EQUAL(ids.size(), 1U);
    BOOST_CHECK_EQUAL(ids[0], "c-1");
}

BOOST_AUTO_TEST_CASE(conflict_keeps_first_body)
{
    modelnet::SwarmDurableLog log;
    std::string err = "prior";
    BOOST_CHECK(log.Commit("coord-a", 1, "c-1", "body-a", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-a", 2, "c-1", "body-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(log.Count(), 1);

    err = "prior";
    BOOST_CHECK(log.Commit("coord-b", 2, "c-2", "body-c", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(log.Count(), 2);

    std::vector<std::string> ids;
    bool continues = false;
    err = "prior";
    BOOST_CHECK(log.Read("coord-a", 2, ids, continues, err));
    BOOST_CHECK(continues);
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE_EQUAL(ids.size(), 2U);
    BOOST_CHECK_EQUAL(ids[0], "c-1");
    BOOST_CHECK_EQUAL(ids[1], "c-2");

    err = "prior";
    BOOST_CHECK(log.Commit("coord-a", 2, "c-1", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(log.Count(), 2);

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-a", 2, "c-1", "body-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(log.Count(), 2);
}

BOOST_AUTO_TEST_CASE(idempotent_commit)
{
    modelnet::SwarmDurableLog log;
    std::string err = "prior";
    BOOST_CHECK(log.Commit("coord-a", 3, "c-1", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(log.Count(), 1);

    err = "prior";
    BOOST_CHECK(log.Commit("coord-b", 3, "c-1", "body-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(log.Count(), 1);

    err = "prior";
    BOOST_CHECK(!log.Commit("coord-a", 2, "c-2", "body-b", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(log.Count(), 1);
}

BOOST_AUTO_TEST_CASE(read_different_coordinator_at_epoch)
{
    modelnet::SwarmDurableLog log;
    std::string err;
    BOOST_CHECK(log.Commit("coord-a", 4, "c-1", "body-a", err));

    std::vector<std::string> ids{"leftover"};
    bool continues = false;
    err = "prior";
    BOOST_CHECK(log.Read("coord-b", 4, ids, continues, err));
    BOOST_CHECK(continues);
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE_EQUAL(ids.size(), 1U);
    BOOST_CHECK_EQUAL(ids[0], "c-1");
}

BOOST_AUTO_TEST_CASE(read_lower_epoch_is_stale)
{
    modelnet::SwarmDurableLog log;
    std::string err;
    BOOST_CHECK(log.Commit("coord-a", 4, "c-1", "body-a", err));

    std::vector<std::string> ids{"leftover"};
    bool continues = true;
    err = "prior";
    BOOST_CHECK(!log.Read("coord-a", 3, ids, continues, err));
    BOOST_CHECK(!continues);
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK(ids.empty());
    BOOST_CHECK_EQUAL(log.Count(), 1);

    continues = false;
    err = "prior";
    BOOST_CHECK(log.Read("coord-b", 4, ids, continues, err));
    BOOST_CHECK(continues);
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE_EQUAL(ids.size(), 1U);
    BOOST_CHECK_EQUAL(ids[0], "c-1");
}

BOOST_AUTO_TEST_CASE(empty_log_read_is_empty)
{
    modelnet::SwarmDurableLog log;
    std::vector<std::string> ids{"leftover"};
    bool continues = true;
    std::string err = "prior";
    BOOST_CHECK(!log.Read("coord-a", 1, ids, continues, err));
    BOOST_CHECK(!continues);
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK(ids.empty());
    BOOST_CHECK_EQUAL(log.Count(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
