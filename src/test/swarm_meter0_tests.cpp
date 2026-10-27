// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_meter0.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_meter0_tests, BasicTestingSetup)

static modelnet::SwarmMeter0 NotedMeter()
{
    modelnet::SwarmMeter0 note;
    note.node_id = "node-1";
    note.measurement_supplied = true;
    note.want_invent = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_meter)
{
    modelnet::SwarmMeter0 note = NotedMeter();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmMeter0Result result = modelnet::SwarmNoteMeter0(note, err);
    BOOST_CHECK_EQUAL(result.code, "METER");
    BOOST_CHECK_EQUAL(result.electricity_atoms, 0);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(err, "METER");
}

BOOST_AUTO_TEST_CASE(want_invent_with_measurement_supplied_is_invented)
{
    modelnet::SwarmMeter0 note = NotedMeter();
    note.measurement_supplied = true;
    note.want_invent = true;
    std::string err = "prior";
    const modelnet::SwarmMeter0Result result = modelnet::SwarmNoteMeter0(note, err);
    BOOST_CHECK_EQUAL(result.code, "INVENTED");
    BOOST_CHECK_EQUAL(result.electricity_atoms, 0);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(err, "INVENTED");
}

BOOST_AUTO_TEST_CASE(missing_measurement_is_unmeasured)
{
    modelnet::SwarmMeter0 note = NotedMeter();
    note.measurement_supplied = false;
    note.want_invent = false;
    std::string err = "prior";
    const modelnet::SwarmMeter0Result result = modelnet::SwarmNoteMeter0(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(result.electricity_atoms, 0);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(supplied_measurement_without_invent_is_noted)
{
    modelnet::SwarmMeter0 note = NotedMeter();
    std::string err = "prior";
    const modelnet::SwarmMeter0Result result = modelnet::SwarmNoteMeter0(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.electricity_atoms, 0);
    BOOST_CHECK(!result.recorded);
}

BOOST_AUTO_TEST_SUITE_END()
