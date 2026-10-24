// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_appointment.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(swarm_appointment_tests, BasicTestingSetup)

namespace {

struct ScratchDir {
    fs::path path;
    ScratchDir()
    {
        path = fs::temp_directory_path();
        path /= fs::u8path("btx-swarm-appointment-" + std::to_string(::getpid()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~ScratchDir() { fs::remove_all(path); }
};

modelnet::SwarmAppointment Sample()
{
    modelnet::SwarmAppointment appointment;
    appointment.channel_id = "chan-1";
    appointment.sequence = 1;
    appointment.contest_blocks = 160;
    appointment.native_remedy_available = false;
    appointment.secp_penalty = false;
    appointment.action = "HASHLOCK_REMEDY";
    return appointment;
}

} // namespace

BOOST_AUTO_TEST_CASE(contest_blocks_80_is_contest_window)
{
    const ScratchDir scratch;
    modelnet::SwarmAppointment appointment = Sample();
    appointment.contest_blocks = 80;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmWriteAppointment(scratch.path, appointment, err));
    BOOST_CHECK_EQUAL(err, "CONTEST_WINDOW");
}

BOOST_AUTO_TEST_CASE(native_remedy_available_is_refused)
{
    const ScratchDir scratch;
    modelnet::SwarmAppointment appointment = Sample();
    appointment.native_remedy_available = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmWriteAppointment(scratch.path, appointment, err));
    BOOST_CHECK_EQUAL(err, "NATIVE_REMEDY");
}

BOOST_AUTO_TEST_CASE(hashlock_remedy_writes_and_reads_back)
{
    const ScratchDir scratch;
    modelnet::SwarmAppointment appointment = Sample();
    appointment.channel_id = "chan-hashlock";
    appointment.sequence = 2;
    appointment.contest_blocks = 160;
    appointment.native_remedy_available = false;
    appointment.secp_penalty = false;
    appointment.action = "HASHLOCK_REMEDY";
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmWriteAppointment(scratch.path, appointment, err));

    const fs::path saved = scratch.path / "swarm" / "appointment.json";
    std::ifstream in(saved);
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK_EQUAL(root["automatic_spend_atoms"].get_str(), "0");
    BOOST_CHECK(!root["native_remedy_available"].get_bool());
    BOOST_CHECK(!root["secp_penalty"].get_bool());

    modelnet::SwarmAppointment loaded;
    BOOST_REQUIRE(modelnet::SwarmReadAppointment(scratch.path, loaded, err));
    BOOST_CHECK_EQUAL(loaded.channel_id, "chan-hashlock");
    BOOST_CHECK_EQUAL(loaded.sequence, 2);
    BOOST_CHECK_EQUAL(loaded.contest_blocks, 160);
    BOOST_CHECK(!loaded.native_remedy_available);
    BOOST_CHECK(!loaded.secp_penalty);
    BOOST_CHECK_EQUAL(loaded.action, "HASHLOCK_REMEDY");
}

BOOST_AUTO_TEST_CASE(second_read_of_the_same_directory)
{
    const ScratchDir scratch;
    modelnet::SwarmAppointment appointment = Sample();
    appointment.channel_id = "chan-reread";
    appointment.sequence = 5;
    appointment.contest_blocks = 160;
    appointment.action = "DRAIN_AND_NOTIFY";
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmWriteAppointment(scratch.path, appointment, err));

    modelnet::SwarmAppointment first;
    BOOST_REQUIRE(modelnet::SwarmReadAppointment(scratch.path, first, err));
    modelnet::SwarmAppointment second;
    BOOST_REQUIRE(modelnet::SwarmReadAppointment(scratch.path, second, err));
    BOOST_CHECK_EQUAL(second.sequence, first.sequence);
    BOOST_CHECK_EQUAL(second.action, first.action);
    BOOST_CHECK_EQUAL(second.sequence, 5);
    BOOST_CHECK_EQUAL(second.action, "DRAIN_AND_NOTIFY");
}

BOOST_AUTO_TEST_SUITE_END()
