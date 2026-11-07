// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/earlyhalt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_earlyhalt_realm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero_and_gpu_stays_false)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());

    BOOST_REQUIRE(plane.Open(3, err));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());

    BOOST_REQUIRE(plane.Step(4, err));
    BOOST_REQUIRE(plane.Step(4, err));
    BOOST_REQUIRE(plane.Promote(err));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.score(), 4);

    BOOST_REQUIRE(plane.Step(3, err));
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 3);
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);
}

BOOST_AUTO_TEST_CASE(realm_promotion_is_refused)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.PromoteRealm(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    BOOST_REQUIRE(plane.Open(2, err));
    BOOST_REQUIRE(plane.Step(8, err));
    BOOST_REQUIRE(plane.Step(8, err));
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 8);
    BOOST_REQUIRE(!plane.early_stop());

    const modelnet::SwarmEarlyHalt& view = plane;
    err = "prior";
    BOOST_REQUIRE(!view.PromoteRealm(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 2);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 8);
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    BOOST_REQUIRE(plane.Promote(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());

    err = "prior";
    BOOST_REQUIRE(!plane.PromoteRealm(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.score(), 8);
    BOOST_REQUIRE_EQUAL(plane.budget(), 2);
    BOOST_REQUIRE(plane.opened());
}

BOOST_AUTO_TEST_SUITE_END()
