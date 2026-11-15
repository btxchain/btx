// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_meter.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_meter_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_caller_supplied_watt_figure_is_not_a_measurement)
{
    std::string err;
    const modelnet::SwarmMeterReading reading = modelnet::SwarmReadResourceMeter(250, err);
    BOOST_CHECK(!reading.measured);
    BOOST_CHECK_EQUAL(reading.watts, 0);
    BOOST_CHECK_EQUAL(reading.wear, 0);
    BOOST_CHECK_EQUAL(reading.network_atoms, 0);
    BOOST_CHECK_EQUAL(reading.code, "METER_ABSENT");
    BOOST_CHECK_EQUAL(err, "METER_ABSENT");
}

BOOST_AUTO_TEST_CASE(zero_is_still_not_a_measurement)
{
    std::string err;
    const modelnet::SwarmMeterReading reading = modelnet::SwarmReadResourceMeter(0, err);
    BOOST_CHECK(!reading.measured);
    BOOST_CHECK_EQUAL(reading.code, "METER_ABSENT");
}

BOOST_AUTO_TEST_SUITE_END()
