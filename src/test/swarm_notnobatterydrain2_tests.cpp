// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobatterydrain2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnobatterydrain2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_governor_id_is_governor)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBatteryDrain2 note;
    note.battery = true;
    note.want_keep = true;
    const modelnet::SwarmNotNoBatteryDrain2Result result = modelnet::SwarmNoteNotNoBatteryDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "GOVERNOR");
    BOOST_CHECK_EQUAL(err, "GOVERNOR");
}

BOOST_AUTO_TEST_CASE(battery_true_want_keep_false_is_drained)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBatteryDrain2 note;
    note.governor_id = "governor-note";
    note.battery = true;
    note.want_keep = false;
    const modelnet::SwarmNotNoBatteryDrain2Result result = modelnet::SwarmNoteNotNoBatteryDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAINED");
    BOOST_CHECK_EQUAL(err, "DRAINED");
}

BOOST_AUTO_TEST_CASE(want_keep_true_battery_false_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBatteryDrain2 note;
    note.governor_id = "governor-note";
    note.battery = false;
    note.want_keep = true;
    const modelnet::SwarmNotNoBatteryDrain2Result result = modelnet::SwarmNoteNotNoBatteryDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoBatteryDrain2 note;
    note.governor_id = "governor-note";
    note.battery = false;
    note.want_keep = false;
    const modelnet::SwarmNotNoBatteryDrain2Result result = modelnet::SwarmNoteNotNoBatteryDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
