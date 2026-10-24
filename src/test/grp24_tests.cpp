// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp24/grp24.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp24& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp24_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_P2P_SCN_K)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "promote", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-K"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "");
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "activate", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "stage", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("P2P-SCN-K", "stage", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-a");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-K"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "stage", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-a");
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-a");
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "activate", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-a");
    BOOST_CHECK(eng.Apply("P2P-SCN-K", "stage", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-b");
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "activate", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-b");
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "rollback", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-b");
    BOOST_CHECK(eng.Apply("P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-a");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-K"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "gen-a");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-K"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_L)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-L", "", "hosted-team", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SERVICE");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-L"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-L"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-L"));
    BOOST_CHECK(eng.Apply("P2P-SCN-L", "", "native-team", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-L"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-L"), "native-team");
    BOOST_CHECK(!eng.Apply("P2P-SCN-L", "", "still-hosted", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SERVICE");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-L"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-L"), "native-team");
    BOOST_CHECK(!eng.Apply("P2P-SCN-L", "", "other-team", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-L"), "native-team");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-L"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_M)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-M", "settle", "funded", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-M"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-M"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-M"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-M", "", "again", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-M"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-M"), "");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-M"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_N)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-N", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-N"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-N"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-N"));
    BOOST_CHECK(eng.Apply("P2P-SCN-N", "", "committed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-N"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-N"), "committed");
    BOOST_CHECK(!eng.Apply("P2P-SCN-N", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-N"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-N"), "committed");
    BOOST_CHECK(!eng.Apply("P2P-SCN-N", "exit", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-N"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-N"), "committed");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-N"));
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-N"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_O)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-O", "", "default", "extra-flag", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FLAG");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-O"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-O"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-O"));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.Apply("P2P-SCN-O", "", "custom", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FLAG");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-O"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-O"), "");
    BOOST_CHECK(eng.Apply("P2P-SCN-O", "", "default", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-O"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-O"), "default");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.Apply("P2P-SCN-O", "", "default", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-O"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-O"), "default");
    BOOST_CHECK(!eng.Apply("P2P-SCN-O", "", "default", "extra-flag", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FLAG");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-O"), "default");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-O"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_P)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-P", "gpu", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-P"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-P"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-P"));
    BOOST_CHECK(eng.Apply("P2P-SCN-P", "observe", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-P"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-P"), "observer");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Apply("P2P-SCN-P", "observe", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-P"), "observer");
    BOOST_CHECK(!eng.Apply("P2P-SCN-P", "gpu", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-P"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-P"), "observer");
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-P"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_Q)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-Q", "", "discovery coordination inference", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CORE");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-Q"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-Q"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-Q"));
    const std::string complete = "discovery coordination inference defense";
    BOOST_CHECK(eng.Apply("P2P-SCN-Q", "", complete, "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-Q"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-Q"), complete);
    BOOST_CHECK(!eng.Apply("P2P-SCN-Q", "", "defense inference coordination discovery", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-Q"), complete);
    BOOST_CHECK(!eng.Apply("P2P-SCN-Q", "remove", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-Q"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-Q"), complete);
    BOOST_CHECK(!eng.bit_of("P2P-SCN-Q"));
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-Q"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_R)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-R", "", "present", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-R"));
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-R"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-R"), "");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(eng.Apply("P2P-SCN-R", "", "present", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-R"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-R"), "present");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-R"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("P2P-SCN-R", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-R"), "present");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-R"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-R", "", "present", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-R"));
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-R"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-R"), "present");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-R"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ISL_004)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(-5), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-004"), "");
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-004"), "");
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(eng.Apply("NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-004"), "cost");
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-ISL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-004"), "cost");
    BOOST_CHECK(!eng.Apply("NIF-ISL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-004"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.Apply("NIF-ISL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(8), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-004"), "cost");
    BOOST_CHECK(!eng.hardware_qualified());
    modelnet::Grp24 flat;
    BOOST_CHECK(flat.Apply("NIF-ISL-004", "", "flat", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(flat.stored("NIF-ISL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(flat.text_of("NIF-ISL-004"), "flat");
    BOOST_CHECK(!flat.hardware_qualified());
    BOOST_CHECK(!flat.Apply("NIF-ISL-004", "", "flat", "", static_cast<int64_t>(0), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(flat.stored("NIF-ISL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(flat.text_of("NIF-ISL-004"), "flat");
    BOOST_CHECK_EQUAL(eng.classification("NIF-ISL-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_001)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-LAN-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-001"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(eng.Apply("NIF-LAN-001", "", "announce", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-001"), "local");
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("NIF-LAN-001", "", "again", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-001"), "local");
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_002)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-LAN-002", "", "multicast", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-002"));
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-002"), "");
    BOOST_CHECK(!eng.Apply("NIF-LAN-002", "", "elsewhere", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-002"));
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("NIF-LAN-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-002"), "local");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-002"));
    BOOST_CHECK(!eng.Apply("NIF-LAN-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-002"), "local");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-002"));
    BOOST_CHECK(!eng.Apply("NIF-LAN-002", "", "multicast", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-002"));
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-002"), "local");
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_007)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-007", "", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-007"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-007"));
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Apply("NIF-QA-007", "promote", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-007"), "");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_004)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARAM");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-004"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "", "", "shape", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARAM");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "", "shape", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-004"), "");
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "", "shape", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DT-CKP-004", "", "shape", "shape", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-004"), "shape");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "", "shape", "shape", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-004"), "shape");
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "", "shape", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-004"), "shape");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_003)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-003", "", "image", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-003"));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Apply("DT-REL-003", "ship", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-003"), "");
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_007)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-007", "", "gpu lan wan security payment", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-007"));
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Apply("DT-REL-007", "", "partial", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-007"), "");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp24 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK(!eng.Apply("NO-SUCH", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.classification("NO-SUCH"), "COMPONENT");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-K"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
