// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/idledrain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_idledrain_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_starts_one_worker)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(!plane.drained());
    BOOST_REQUIRE_EQUAL(plane.workers(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(!plane.drained());
    BOOST_REQUIRE_EQUAL(plane.workers(), 1);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(second_open_leaves_the_current_count)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 3);

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(!plane.drained());
    BOOST_REQUIRE_EQUAL(plane.workers(), 3);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 3);
}

BOOST_AUTO_TEST_CASE(second_open_at_the_start_count_is_replay)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE_EQUAL(plane.workers(), 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.workers(), 1);
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(!plane.drained());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(first_open_assigns_one_after_admits)
{
    modelnet::SwarmIdleDrain plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Admit(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.workers(), 2);
    BOOST_REQUIRE(!plane.opened());

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.workers(), 1);
    BOOST_REQUIRE(!plane.drained());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
