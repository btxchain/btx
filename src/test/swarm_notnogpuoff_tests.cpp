// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogpuoff.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogpuoff_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_device_id)
{
    modelnet::SwarmNotNoGpuOff note;
    note.device_json = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuOffResult result = modelnet::SwarmNoteNotNoGpuOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "DEVICE");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "DEVICE");
}

BOOST_AUTO_TEST_CASE(device_json_false)
{
    modelnet::SwarmNotNoGpuOff note;
    note.device_id = "device-1";
    note.device_json = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuOffResult result = modelnet::SwarmNoteNotNoGpuOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(want_train)
{
    modelnet::SwarmNotNoGpuOff note;
    note.device_id = "device-1";
    note.device_json = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuOffResult result = modelnet::SwarmNoteNotNoGpuOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoGpuOff note;
    note.device_id = "device-1";
    note.device_json = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuOffResult result = modelnet::SwarmNoteNotNoGpuOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
