// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/earlyhalt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_earlyhalt_promote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(promote_before_a_step_is_step)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Promote(err));
    BOOST_REQUIRE_EQUAL(err, "STEP");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(!plane.has_score());
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE(!plane.graduated());

    BOOST_REQUIRE(plane.Open(3, err));
    err = "prior";
    BOOST_REQUIRE(!plane.Promote(err));
    BOOST_REQUIRE_EQUAL(err, "STEP");
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 3);
    BOOST_REQUIRE(!plane.has_score());
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
}

BOOST_AUTO_TEST_CASE(promote_after_early_stop_is_refused)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(4, err));
    BOOST_REQUIRE(plane.Step(30, err));
    BOOST_REQUIRE(plane.Step(29, err));
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.score(), 29);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.budget(), 4);

    const modelnet::SwarmEarlyHalt& view = plane;
    err = "prior";
    BOOST_REQUIRE(!view.Promote(err));
    BOOST_REQUIRE_EQUAL(err, "STOPPED");
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.score(), 29);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.budget(), 4);
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());

    err = "prior";
    BOOST_REQUIRE(!plane.Promote(err));
    BOOST_REQUIRE_EQUAL(err, "STOPPED");
    BOOST_REQUIRE_EQUAL(plane.score(), 29);
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.budget(), 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Open(8, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.budget(), 4);
    BOOST_REQUIRE_EQUAL(plane.score(), 29);
    BOOST_REQUIRE(plane.early_stop());
}

BOOST_AUTO_TEST_CASE(nondecreasing_run_promotes_with_remaining_zero)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(3, err));
    BOOST_REQUIRE(plane.Step(5, err));
    BOOST_REQUIRE_EQUAL(plane.remaining(), 2);
    BOOST_REQUIRE_EQUAL(plane.score(), 5);
    BOOST_REQUIRE(!plane.early_stop());

    BOOST_REQUIRE(plane.Promote(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 2);
    BOOST_REQUIRE_EQUAL(plane.score(), 5);
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);

    BOOST_REQUIRE(plane.Step(5, err));
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 1);
    BOOST_REQUIRE_EQUAL(plane.score(), 5);

    BOOST_REQUIRE(plane.Step(6, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 6);
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);

    BOOST_REQUIRE(plane.Promote(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 6);
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());

    err = "prior";
    BOOST_REQUIRE(!plane.Step(9, err));
    BOOST_REQUIRE_EQUAL(err, "STOPPED");
    BOOST_REQUIRE_EQUAL(plane.score(), 6);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE(!plane.early_stop());

    BOOST_REQUIRE(plane.Promote(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.score(), 6);
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);
}

BOOST_AUTO_TEST_SUITE_END()
