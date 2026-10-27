// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/limits.h>
#include <modelnet/swarm_dupreceipt/quiet.h>
#include <modelnet/swarm_dupreceipt/swarm_dupreceipt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireQuiet(const modelnet::SwarmDupReceipt& plane)
{
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_dupreceipt_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero)
{
    BOOST_REQUIRE(!modelnet::kSwarmDupBroadcast);
    BOOST_REQUIRE(!modelnet::kSwarmDupMined);
    BOOST_REQUIRE_EQUAL(modelnet::kSwarmDupBytesMoved, 0);
    BOOST_REQUIRE_EQUAL(std::string{modelnet::kSwarmDupAutomaticSpend}, "0");

    modelnet::SwarmDupQuiet quiet;
    BOOST_REQUIRE(!quiet.broadcast());
    BOOST_REQUIRE(!quiet.mined());
    BOOST_REQUIRE_EQUAL(quiet.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(quiet.automatic_spend(), "0");

    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";
    RequireQuiet(plane);

    BOOST_REQUIRE(plane.Bind("rcpt-1", err));
    BOOST_REQUIRE(err.empty());
    RequireQuiet(plane);
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("rcpt-1", 2, true, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    RequireQuiet(plane);
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE(!plane.paid("rcpt-1"));

    err = "prior";
    BOOST_REQUIRE(plane.Pay("rcpt-1", 2, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.earned(), 2);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("rcpt-1", 2, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.earned(), 2);
    RequireQuiet(plane);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
