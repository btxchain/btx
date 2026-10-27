// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lanwire/swarm_lanwire.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> BtxLan()
{
    const std::string text = "btx-lan";
    return std::vector<unsigned char>(text.begin(), text.end());
}

void ExpectQuiet(const modelnet::SwarmLanWire& wire)
{
    BOOST_CHECK(!wire.launched());
    BOOST_CHECK(!wire.gpu());
    BOOST_CHECK(!wire.broadcast());
    BOOST_CHECK(!wire.connected());
    BOOST_CHECK(!wire.wan_received());
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
}

} // namespace

BOOST_AUTO_TEST_SUITE(swarm_lanwire_tests)

BOOST_FIXTURE_TEST_CASE(exchange_round_trips_btx_lan, BasicTestingSetup)
{
    modelnet::SwarmLanWire wire;
    const std::vector<unsigned char> payload = BtxLan();
    std::string err = "prior";

    BOOST_REQUIRE(wire.Exchange(payload, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(wire.received() == payload);
    BOOST_CHECK_EQUAL(wire.packets(), static_cast<int64_t>(1));
    BOOST_CHECK(wire.local_received());
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<int64_t>(payload.size()));
    ExpectQuiet(wire);
}

BOOST_FIXTURE_TEST_CASE(empty_payload_is_payload, BasicTestingSetup)
{
    modelnet::SwarmLanWire wire;
    std::string err = "prior";

    BOOST_CHECK(!wire.Exchange({}, err));
    BOOST_CHECK_EQUAL(err, "PAYLOAD");
    BOOST_CHECK(wire.received().empty());
    BOOST_CHECK(!wire.local_received());
    BOOST_CHECK_EQUAL(wire.packets(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<int64_t>(0));
    ExpectQuiet(wire);
}

BOOST_FIXTURE_TEST_CASE(wan_is_no_route, BasicTestingSetup)
{
    modelnet::SwarmLanWire wire;
    std::string err = "prior";

    BOOST_CHECK(!wire.Wan(err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK(!wire.wan_received());
    BOOST_CHECK(!wire.local_received());
    BOOST_CHECK_EQUAL(wire.packets(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<int64_t>(0));
    ExpectQuiet(wire);
}

BOOST_FIXTURE_TEST_CASE(scan_is_not_scan, BasicTestingSetup)
{
    modelnet::SwarmLanWire wire;
    std::string err = "prior";

    BOOST_CHECK(!wire.Scan("prefix", err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK(wire.received().empty());
    BOOST_CHECK(!wire.local_received());
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    ExpectQuiet(wire);
}

BOOST_FIXTURE_TEST_CASE(automatic_spend_is_zero, BasicTestingSetup)
{
    modelnet::SwarmLanWire wire;
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<int64_t>(0));
    ExpectQuiet(wire);
}

BOOST_AUTO_TEST_SUITE_END()
