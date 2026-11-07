// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/swarm_paylabel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paylabel_accept_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(work_payment_is_stored)
{
    modelnet::SwarmPayLabel plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.accepted());
    BOOST_REQUIRE(plane.label().empty());
    BOOST_REQUIRE_EQUAL(plane.atoms(), 0);

    BOOST_REQUIRE(plane.Accept("work-payment", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.accepted());
    BOOST_REQUIRE_EQUAL(plane.label(), "work-payment");
    BOOST_REQUIRE_EQUAL(plane.atoms(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
