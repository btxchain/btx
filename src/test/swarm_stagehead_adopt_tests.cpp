// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/stagehead.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_stagehead_adopt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(adopt_without_candidate_leaves_active)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Adopt(true, err));
    BOOST_REQUIRE_EQUAL(err, "ADOPT");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(plane.previous().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Adopt(false, err));
    BOOST_REQUIRE_EQUAL(err, "ADOPT");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(incompatible_adopt_stays_unadopted)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("next", err));
    BOOST_REQUIRE(!plane.Adopt(false, err));
    BOOST_REQUIRE_EQUAL(err, "LOCAL_INCOMPATIBLE");
    BOOST_REQUIRE_EQUAL(plane.staged(), "next");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Adopt(false, err));
    BOOST_REQUIRE_EQUAL(err, "LOCAL_INCOMPATIBLE");
    BOOST_REQUIRE_EQUAL(plane.staged(), "next");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
}

BOOST_AUTO_TEST_CASE(successful_adopt_remembers_previous_and_clears_staged)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("next", err));
    BOOST_REQUIRE(!plane.Adopt(false, err));
    BOOST_REQUIRE_EQUAL(plane.staged(), "next");

    err = "prior";
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Adopt(true, err));
    BOOST_REQUIRE_EQUAL(err, "ADOPT");
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");
}

BOOST_AUTO_TEST_CASE(second_adopt_remembers_the_id_it_replaced)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("next", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE(plane.Stage("later", err));
    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "later");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE_EQUAL(plane.previous(), "next");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
