// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rollback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rollback_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stage_leaves_active_at_base)
{
    modelnet::SwarmRollback roll;
    BOOST_CHECK_EQUAL(roll.active(), "base");

    std::string err = "prior";
    BOOST_CHECK(!roll.Stage("", err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_CHECK_EQUAL(roll.active(), "base");

    err = "prior";
    BOOST_CHECK(roll.Stage("cand-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "base");

    err = "prior";
    BOOST_CHECK(!roll.Stage("", err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_CHECK_EQUAL(roll.active(), "base");
}

BOOST_AUTO_TEST_CASE(adopt_then_rollback_to_base)
{
    modelnet::SwarmRollback roll;
    std::string err = "prior";
    BOOST_CHECK(!roll.Adopt(err));
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK_EQUAL(roll.active(), "base");

    BOOST_CHECK(roll.Stage("cand-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "base");

    err = "prior";
    BOOST_CHECK(roll.Adopt(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "cand-a");

    err = "prior";
    BOOST_CHECK(!roll.Adopt(err));
    BOOST_CHECK_EQUAL(err, "STAGE");
    BOOST_CHECK_EQUAL(roll.active(), "cand-a");

    err = "prior";
    BOOST_CHECK(roll.Rollback(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "base");
}

BOOST_AUTO_TEST_CASE(second_rollback_without_newer_adopt_is_refused)
{
    modelnet::SwarmRollback roll;
    std::string err = "prior";
    BOOST_CHECK(!roll.Rollback(err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(roll.active(), "base");

    BOOST_CHECK(roll.Stage("cand-a", err));
    BOOST_CHECK(roll.Adopt(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "cand-a");

    err = "prior";
    BOOST_CHECK(roll.Rollback(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "base");

    err = "prior";
    BOOST_CHECK(!roll.Rollback(err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(roll.active(), "base");

    err = "prior";
    BOOST_CHECK(roll.Stage("cand-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "base");
    BOOST_CHECK(roll.Adopt(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "cand-b");

    err = "prior";
    BOOST_CHECK(roll.Rollback(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(roll.active(), "base");

    err = "prior";
    BOOST_CHECK(!roll.Rollback(err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(roll.active(), "base");
}

BOOST_AUTO_TEST_SUITE_END()
