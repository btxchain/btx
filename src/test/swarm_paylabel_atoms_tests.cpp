// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/limits.h>
#include <modelnet/swarm_paylabel/quiet.h>
#include <modelnet/swarm_paylabel/swarm_paylabel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paylabel_atoms_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(atoms_stay_zero)
{
    BOOST_REQUIRE_EQUAL(modelnet::kSwarmPayLabelAtoms, 0);
    BOOST_REQUIRE_EQUAL(modelnet::SwarmPayLabelQuiet{}.atoms(), 0);
    BOOST_REQUIRE_EQUAL(modelnet::SwarmPayLabelQuiet{}.automatic_spend(), "0");
    BOOST_REQUIRE(!modelnet::SwarmPayLabelQuiet{}.broadcast());
    BOOST_REQUIRE_EQUAL(modelnet::SwarmPayLabelQuiet{}.bytes_moved(), 0);

    modelnet::SwarmPayLabel plane;
    BOOST_REQUIRE_EQUAL(plane.atoms(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    std::string err = "prior";
    BOOST_REQUIRE(!plane.Accept("profit-share", err));
    BOOST_REQUIRE_EQUAL(err, "REFUSED");
    BOOST_REQUIRE_EQUAL(plane.atoms(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Accept("", err));
    BOOST_REQUIRE_EQUAL(err, "LABEL");
    BOOST_REQUIRE_EQUAL(plane.atoms(), 0);

    err = "prior";
    BOOST_REQUIRE(plane.Accept("work-payment", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.label(), "work-payment");
    BOOST_REQUIRE_EQUAL(plane.atoms(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Accept("work-payment", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.atoms(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
