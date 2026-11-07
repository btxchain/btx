// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_eleccost.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_eleccost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_meter_is_meter)
{
    modelnet::SwarmElecCost meter;
    meter.measured = true;
    meter.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmElecCostResult result = modelnet::SwarmNoteElecCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "METER");
    BOOST_CHECK_EQUAL(err, "METER");
}

BOOST_AUTO_TEST_CASE(unmeasured_without_charge_is_held)
{
    modelnet::SwarmElecCost meter;
    meter.meter_id = "meter-1";
    meter.measured = false;
    meter.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmElecCostResult result = modelnet::SwarmNoteElecCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_charge_is_held)
{
    modelnet::SwarmElecCost meter;
    meter.meter_id = "meter-1";
    meter.measured = true;
    meter.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmElecCostResult result = modelnet::SwarmNoteElecCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(measured_note_is_noted)
{
    modelnet::SwarmElecCost meter;
    meter.meter_id = "meter-1";
    meter.measured = true;
    meter.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmElecCostResult result = modelnet::SwarmNoteElecCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
