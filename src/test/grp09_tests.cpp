// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp09/grp09.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp09& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp09_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_DT_WAN_002)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-WAN-002", "", "diloco", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-WAN-002"));
    BOOST_CHECK(eng.Apply("DT-WAN-002", "", "local-sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-002"), "local-sgd");
    BOOST_CHECK(!eng.bit_of("DT-WAN-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-WAN-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_WAN_003)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-WAN-003", "", "local-sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-WAN-003"));
    BOOST_CHECK(eng.Apply("DT-WAN-003", "", "diloco", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-003"), "diloco");
    BOOST_CHECK(!eng.bit_of("DT-WAN-003"));
    BOOST_CHECK(!eng.Apply("DT-WAN-003", "qualify", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-003"), "diloco");
    BOOST_CHECK(!eng.bit_of("DT-WAN-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-WAN-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_WAN_004)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-WAN-004", "", "a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-004"), "a");
    BOOST_CHECK(!eng.bit_of("DT-WAN-004"));
    BOOST_CHECK(!eng.Apply("DT-WAN-004", "replace", "c", "b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SYNC");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-004"), "a");
    BOOST_CHECK(!eng.bit_of("DT-WAN-004"));
    BOOST_CHECK(eng.Apply("DT-WAN-004", "replace", "c", "a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-004"), "c");
    BOOST_CHECK(!eng.bit_of("DT-WAN-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-WAN-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_WAN_005)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-WAN-005", "commit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-005"), "commit");
    BOOST_CHECK(!eng.bit_of("DT-WAN-005"));
    BOOST_CHECK(eng.Apply("DT-WAN-005", "partition", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-005"), "partition");
    BOOST_CHECK(eng.bit_of("DT-WAN-005"));
    BOOST_CHECK(!eng.Apply("DT-WAN-005", "commit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARTITION");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-005"), "partition");
    BOOST_CHECK(eng.bit_of("DT-WAN-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-WAN-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_WAN_007)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-WAN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EPOCH");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-WAN-007"));
    BOOST_CHECK(!eng.Apply("DT-WAN-007", "", "e1", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-WAN-007"));
    BOOST_CHECK(eng.Apply("DT-WAN-007", "", "e1", "", static_cast<int64_t>(0), static_cast<int64_t>(2), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-007"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-007"), "e1");
    BOOST_CHECK(!eng.bit_of("DT-WAN-007"));
    BOOST_CHECK(!eng.Apply("DT-WAN-007", "", "e2", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-007"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-007"), "e1");
    BOOST_CHECK(!eng.bit_of("DT-WAN-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-WAN-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_WAN_008)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-WAN-008", "m", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-WAN-008"));
    BOOST_CHECK(eng.Apply("DT-WAN-008", "fork", "child", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-008"), "fork");
    BOOST_CHECK(!eng.bit_of("DT-WAN-008"));
    BOOST_CHECK(eng.Apply("DT-WAN-008", "distill", "teacher", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-008"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-008"), "distill");
    BOOST_CHECK(!eng.bit_of("DT-WAN-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-WAN-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_001)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "IDENTITY");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-001"));
    BOOST_CHECK(eng.Apply("DT-SEC-001", "", "signed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-001"), "signed");
    BOOST_CHECK(!eng.bit_of("DT-SEC-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_002)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-002", "norm", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NORM");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-002"));
    BOOST_CHECK(!eng.Apply("DT-SEC-002", "sig", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NORM");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_003)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-003", "", "private_trajectory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-003"));
    BOOST_CHECK(eng.Apply("DT-SEC-003", "", "public_trajectory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-003"), "public_trajectory");
    BOOST_CHECK(!eng.bit_of("DT-SEC-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_004)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MANDATE");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-004"));
    BOOST_CHECK(eng.Apply("DT-SEC-004", "", "m1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-004"), "m1");
    BOOST_CHECK(!eng.bit_of("DT-SEC-004"));
    BOOST_CHECK(!eng.Apply("DT-SEC-004", "pay", "m1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-004"), "m1");
    BOOST_CHECK(!eng.bit_of("DT-SEC-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_005)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-005", "", "draft", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-005"));
    BOOST_CHECK(eng.Apply("DT-SEC-005", "", "synthetic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-005"), "synthetic");
    BOOST_CHECK(!eng.bit_of("DT-SEC-005"));
    BOOST_CHECK(eng.Apply("DT-SEC-005", "", "accepted", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-005"), "accepted");
    BOOST_CHECK(eng.bit_of("DT-SEC-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_006)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-006", "download", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOWNLOAD");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-006"));
    BOOST_CHECK(!eng.Apply("DT-SEC-006", "", "elf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-006"));
    BOOST_CHECK(eng.Apply("DT-SEC-006", "", "worker", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-006"), "isolated");
    BOOST_CHECK(!eng.bit_of("DT-SEC-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_007)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-007", "release", "cand", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-007"));
    BOOST_CHECK(eng.Apply("DT-SEC-007", "candidate", "cand", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-007"), "candidate");
    BOOST_CHECK(!eng.bit_of("DT-SEC-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SEC_008)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SEC-008", "arm", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DEADLINE");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-SEC-008"));
    BOOST_CHECK(eng.Apply("DT-SEC-008", "arm", "", "", static_cast<int64_t>(0), static_cast<int64_t>(20), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-008"), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-008"), "deadline");
    BOOST_CHECK(!eng.bit_of("DT-SEC-008"));
    BOOST_CHECK(eng.Apply("DT-SEC-008", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-008"), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-008"), "deadline");
    BOOST_CHECK(!eng.bit_of("DT-SEC-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SEC-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SIM_001)
{
    modelnet::Grp09 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SIM-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ASSUMPTION");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-001"));
    BOOST_CHECK(eng.Apply("DT-SIM-001", "", "slots-not-time", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-001"), "slots-not-time");
    BOOST_CHECK(!eng.bit_of("DT-SIM-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-001"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

