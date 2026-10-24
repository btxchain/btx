// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_masshold.h>
#include <test/util/setup_common.h>

#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_masshold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(channels_or_assumed_bytes_below_one_is_exit)
{
    std::string err = "prior";
    modelnet::SwarmMassExitNote note;
    note.channels = 0;
    note.assumed_bytes = 100;
    note.measured = true;
    note.want_broadcast = true;
    const modelnet::SwarmMassExitResult zero_channels = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!zero_channels.broadcast);
    BOOST_CHECK(!zero_channels.measured_size);
    BOOST_CHECK_EQUAL(zero_channels.code, "EXIT");
    BOOST_CHECK_EQUAL(err, "EXIT");

    note.channels = -2;
    const modelnet::SwarmMassExitResult negative_channels = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!negative_channels.broadcast);
    BOOST_CHECK(!negative_channels.measured_size);
    BOOST_CHECK_EQUAL(negative_channels.code, "EXIT");
    BOOST_CHECK_EQUAL(err, "EXIT");

    note.channels = 4;
    note.assumed_bytes = 0;
    const modelnet::SwarmMassExitResult zero_bytes = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!zero_bytes.broadcast);
    BOOST_CHECK(!zero_bytes.measured_size);
    BOOST_CHECK_EQUAL(zero_bytes.code, "EXIT");
    BOOST_CHECK_EQUAL(err, "EXIT");

    note.assumed_bytes = -8;
    const modelnet::SwarmMassExitResult negative_bytes = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!negative_bytes.broadcast);
    BOOST_CHECK(!negative_bytes.measured_size);
    BOOST_CHECK_EQUAL(negative_bytes.code, "EXIT");
    BOOST_CHECK_EQUAL(err, "EXIT");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_forbidden_even_when_measured)
{
    std::string err = "prior";
    modelnet::SwarmMassExitNote note;
    note.channels = 3;
    note.assumed_bytes = 64;
    note.measured = true;
    note.want_broadcast = true;
    const modelnet::SwarmMassExitResult measured = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!measured.broadcast);
    BOOST_CHECK(!measured.measured_size);
    BOOST_CHECK_EQUAL(measured.code, "BROADCAST_FORBIDDEN");
    BOOST_CHECK_EQUAL(err, "BROADCAST_FORBIDDEN");

    note.measured = false;
    const modelnet::SwarmMassExitResult unmarked = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!unmarked.broadcast);
    BOOST_CHECK(!unmarked.measured_size);
    BOOST_CHECK_EQUAL(unmarked.code, "BROADCAST_FORBIDDEN");
    BOOST_CHECK_EQUAL(err, "BROADCAST_FORBIDDEN");
}

BOOST_AUTO_TEST_CASE(measured_flag_is_refused)
{
    std::string err = "prior";
    modelnet::SwarmMassExitNote note;
    note.channels = 2;
    note.assumed_bytes = 32;
    note.measured = true;
    note.want_broadcast = false;
    const modelnet::SwarmMassExitResult result = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.measured_size);
    BOOST_CHECK_EQUAL(result.code, "MEASURE_REFUSED");
    BOOST_CHECK_EQUAL(err, "MEASURE_REFUSED");
}

BOOST_AUTO_TEST_CASE(assumed_byte_count_is_not_measured_and_is_not_broadcast)
{
    std::string err = "prior";
    modelnet::SwarmMassExitNote note;
    note.channels = 1;
    note.assumed_bytes = 1;
    note.measured = false;
    note.want_broadcast = false;
    const modelnet::SwarmMassExitResult edge = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!edge.broadcast);
    BOOST_CHECK(!edge.measured_size);
    BOOST_CHECK_EQUAL(edge.code, "ASSUMED");
    BOOST_CHECK(err.empty());

    err = "prior";
    note.channels = 8;
    note.assumed_bytes = 4096;
    const modelnet::SwarmMassExitResult larger = modelnet::SwarmNoteMassExit(note, err);
    BOOST_CHECK(!larger.broadcast);
    BOOST_CHECK(!larger.measured_size);
    BOOST_CHECK_EQUAL(larger.code, "ASSUMED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
