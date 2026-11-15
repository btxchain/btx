// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notelectric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notelectric_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_meter_id)
{
    modelnet::SwarmNotElectric note;
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotElectricResult out = modelnet::SwarmNoteNotElectric(note, err);
    BOOST_CHECK_EQUAL(out.code, "METER");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.watt_hours, 0);
    BOOST_CHECK_EQUAL(err, "METER");
}

BOOST_AUTO_TEST_CASE(want_publish_unmeasured)
{
    modelnet::SwarmNotElectric note;
    note.meter_id = "meter-wh";
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotElectricResult out = modelnet::SwarmNoteNotElectric(note, err);
    BOOST_CHECK_EQUAL(out.code, "UNMEASURED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.watt_hours, 0);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotElectric note;
    note.meter_id = "meter-wh";
    std::string err = "stale";
    const modelnet::SwarmNotElectricResult out = modelnet::SwarmNoteNotElectric(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.watt_hours, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
