// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_costmeter.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_costmeter_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cost_id_is_cost)
{
    modelnet::SwarmCostMeter meter;
    meter.electricity_measured = true;
    meter.wear_measured = true;
    meter.network_measured = true;
    meter.electricity = 3;
    meter.wear = 4;
    meter.network = 5;
    meter.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmCostMeterResult result = modelnet::SwarmRecordCostMeter(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.electricity, 0);
    BOOST_CHECK_EQUAL(result.wear, 0);
    BOOST_CHECK_EQUAL(result.network, 0);
    BOOST_CHECK_EQUAL(result.code, "COST");
    BOOST_CHECK_EQUAL(err, "COST");
}

BOOST_AUTO_TEST_CASE(electricity_unmeasured_is_unmeasured)
{
    modelnet::SwarmCostMeter meter;
    meter.cost_id = "cost-1";
    meter.electricity_measured = false;
    meter.wear_measured = true;
    meter.network_measured = true;
    meter.electricity = 9;
    meter.wear = 8;
    meter.network = 7;
    meter.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmCostMeterResult result = modelnet::SwarmRecordCostMeter(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.electricity, 0);
    BOOST_CHECK_EQUAL(result.wear, 0);
    BOOST_CHECK_EQUAL(result.network, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(negative_wear_is_range)
{
    modelnet::SwarmCostMeter meter;
    meter.cost_id = "cost-1";
    meter.electricity_measured = true;
    meter.wear_measured = true;
    meter.network_measured = true;
    meter.electricity = 3;
    meter.wear = -1;
    meter.network = 5;
    meter.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmCostMeterResult result = modelnet::SwarmRecordCostMeter(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.electricity, 0);
    BOOST_CHECK_EQUAL(result.wear, 0);
    BOOST_CHECK_EQUAL(result.network, 0);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(want_charge_is_held)
{
    modelnet::SwarmCostMeter meter;
    meter.cost_id = "cost-1";
    meter.electricity_measured = true;
    meter.wear_measured = true;
    meter.network_measured = true;
    meter.electricity = 3;
    meter.wear = 4;
    meter.network = 5;
    meter.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmCostMeterResult result = modelnet::SwarmRecordCostMeter(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.electricity, 3);
    BOOST_CHECK_EQUAL(result.wear, 4);
    BOOST_CHECK_EQUAL(result.network, 5);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_record_is_noted)
{
    modelnet::SwarmCostMeter meter;
    meter.cost_id = "cost-1";
    meter.electricity_measured = true;
    meter.wear_measured = true;
    meter.network_measured = true;
    meter.electricity = 3;
    meter.wear = 4;
    meter.network = 5;
    meter.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmCostMeterResult result = modelnet::SwarmRecordCostMeter(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.electricity, 3);
    BOOST_CHECK_EQUAL(result.wear, 4);
    BOOST_CHECK_EQUAL(result.network, 5);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
