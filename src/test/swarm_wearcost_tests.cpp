// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearcost.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_wearcost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_meter)
{
    modelnet::SwarmWearCost meter;
    meter.meter_id.clear();
    meter.measured = true;
    meter.want_charge = false;
    std::string err;
    const modelnet::SwarmWearCostResult result = modelnet::SwarmNoteWearCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "METER");
    BOOST_CHECK_EQUAL(err, "METER");
}

BOOST_AUTO_TEST_CASE(unmeasured_want_charge_false)
{
    modelnet::SwarmWearCost meter;
    meter.meter_id = "meter-a";
    meter.measured = false;
    meter.want_charge = false;
    std::string err;
    const modelnet::SwarmWearCostResult result = modelnet::SwarmNoteWearCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_charge_held)
{
    modelnet::SwarmWearCost meter;
    meter.meter_id = "meter-b";
    meter.measured = true;
    meter.want_charge = true;
    std::string err;
    const modelnet::SwarmWearCostResult result = modelnet::SwarmNoteWearCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmWearCost meter;
    meter.meter_id = "meter-c";
    meter.measured = true;
    meter.want_charge = false;
    std::string err = "stale";
    const modelnet::SwarmWearCostResult result = modelnet::SwarmNoteWearCost(meter, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
