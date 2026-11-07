// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_overlaphold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_overlaphold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_edge)
{
    modelnet::SwarmOverlapHold edge;
    edge.edge_id.clear();
    edge.overlapping = false;
    edge.want_claim = false;
    std::string err;
    const modelnet::SwarmOverlapHoldResult result = modelnet::SwarmHoldOverlap(edge, err);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(overlapping_timeout)
{
    modelnet::SwarmOverlapHold edge;
    edge.edge_id = "edge-1";
    edge.overlapping = true;
    edge.want_claim = false;
    std::string err;
    const modelnet::SwarmOverlapHoldResult result = modelnet::SwarmHoldOverlap(edge, err);
    BOOST_CHECK_EQUAL(result.code, "TIMEOUT");
    BOOST_CHECK_EQUAL(err, "TIMEOUT");
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(want_claim_held)
{
    modelnet::SwarmOverlapHold edge;
    edge.edge_id = "edge-2";
    edge.overlapping = false;
    edge.want_claim = true;
    std::string err;
    const modelnet::SwarmOverlapHoldResult result = modelnet::SwarmHoldOverlap(edge, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmOverlapHold edge;
    edge.edge_id = "edge-3";
    edge.overlapping = false;
    edge.want_claim = false;
    std::string err = "stale";
    const modelnet::SwarmOverlapHoldResult result = modelnet::SwarmHoldOverlap(edge, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
