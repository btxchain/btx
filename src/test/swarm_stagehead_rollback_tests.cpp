// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/stagehead.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_stagehead_rollback_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_rollback_then_a_second_is_refused)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());

    err = "prior";
    BOOST_REQUIRE(plane.Stage("next", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");

    err = "prior";
    BOOST_REQUIRE(plane.Stage("side", err));
    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "side");
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "side");
    BOOST_REQUIRE(!plane.mined());
}

BOOST_AUTO_TEST_CASE(rollback_after_two_adopts_restores_one_id)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("next", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE(plane.Stage("later", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE_EQUAL(plane.active(), "later");
    BOOST_REQUIRE_EQUAL(plane.previous(), "next");

    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());

    err = "prior";
    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(regress_restores_once_and_a_second_is_refused)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");

    err = "prior";
    BOOST_REQUIRE(plane.Stage("next", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(!plane.mined());
}

BOOST_AUTO_TEST_CASE(rollback_and_regress_share_one_memory)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("next", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(plane.active(), "base");

    err = "prior";
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());

    err = "prior";
    BOOST_REQUIRE(plane.Stage("side", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE_EQUAL(plane.active(), "base");

    err = "prior";
    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
