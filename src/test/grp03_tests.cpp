// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp03/grp03.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp03& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp03_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_NIF_LAN_005)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("NIF-LAN-005", "scope", "lan", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-005"), "lan");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-005"));
    BOOST_CHECK(eng.Apply("NIF-LAN-005", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-005"), "lan");
    BOOST_CHECK(eng.bit_of("NIF-LAN-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_006)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-LAN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "IFACE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-006"));
    BOOST_CHECK(eng.Apply("NIF-LAN-006", "deny", "eth0", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-006"), "eth0");
    BOOST_CHECK(eng.bit_of("NIF-LAN-006"));
    BOOST_CHECK(!eng.Apply("NIF-LAN-006", "discover", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-006"), "eth0");
    BOOST_CHECK(eng.bit_of("NIF-LAN-006"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_007)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-LAN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "WALLET");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-007"), "");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-007"));
    BOOST_CHECK(eng.Apply("NIF-LAN-007", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-007"), "free");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-007"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_008)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("NIF-LAN-008", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-008"), "local");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-008"));
    BOOST_CHECK(eng.Apply("NIF-LAN-008", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-008"), "local");
    BOOST_CHECK(eng.bit_of("NIF-LAN-008"));
    BOOST_CHECK(!eng.Apply("NIF-LAN-008", "internet", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-008"), "local");
    BOOST_CHECK(eng.bit_of("NIF-LAN-008"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ISL_001)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-ISL-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TOPOLOGY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-001"));
    BOOST_CHECK(eng.Apply("NIF-ISL-001", "", "rtt10", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-001"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-001"), "rtt10");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ISL-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ISL_002)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-ISL-002", "collective", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-002"));
    BOOST_CHECK(eng.Apply("NIF-ISL-002", "collective", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-002"), "local");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ISL-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ISL_003)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("NIF-ISL-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-003"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-003"), "queued");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-003"));
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "BACKPRESSURE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-003"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-003"), "queued");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ISL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ISL_005)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("NIF-ISL-005", "fail", "hello", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-005"), "hello");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-005"));
    BOOST_CHECK(eng.Apply("NIF-ISL-005", "restore", "hello", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-005"), "hello");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-005"));
    BOOST_CHECK(!eng.Apply("NIF-ISL-005", "restore", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ISL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-005"), "hello");
    BOOST_CHECK(!eng.bit_of("NIF-ISL-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ISL-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PKG_001)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-001"));
    BOOST_CHECK(eng.Apply("NIF-PKG-001", "", "ab", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-001"), "ab");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-001"));
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "execute", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-001"), "ab");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PKG-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PKG_002)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PKG-002", "", "zz", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-002"));
    BOOST_CHECK(eng.Apply("NIF-PKG-002", "", "cd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-002"), "cd");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PKG-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PKG_003)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PKG-003", "egress", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-003"));
    BOOST_CHECK(!eng.Apply("NIF-PKG-003", "download", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOWNLOAD");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-003"));
    BOOST_CHECK(!eng.Apply("NIF-PKG-003", "", "PYTHON_PICKLE", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-003"));
    BOOST_CHECK(eng.Apply("NIF-PKG-003", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-003"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-003"), "plain");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PKG-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PKG_004)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PKG-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-004"));
    BOOST_CHECK(!eng.Apply("NIF-PKG-004", "same", "same", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-004"));
    BOOST_CHECK(eng.Apply("NIF-PKG-004", "model", "soft", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-004"), "soft");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PKG-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PKG_005)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("NIF-PKG-005", "bind", "a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-005"), "a");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-005"));
    BOOST_CHECK(eng.Apply("NIF-PKG-005", "bind", "b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-005"), "b");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-005"));
    BOOST_CHECK(eng.Apply("NIF-PKG-005", "rollback", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-005"), "a");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-005"));
    BOOST_CHECK(!eng.Apply("NIF-PKG-005", "rollback", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PKG-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PKG-005"), "a");
    BOOST_CHECK(!eng.bit_of("NIF-PKG-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PKG-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_DATA_001)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-DATA-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENCODING");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-001"));
    BOOST_CHECK(eng.Apply("NIF-DATA-001", "utf8", "utf8", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-001"), "utf8");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-001"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-001", "latin1", "utf8", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENCODING");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-001"), "utf8");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-DATA-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_DATA_002)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-DATA-002", "", "<eos>", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LOOKALIKE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-002"));
    BOOST_CHECK(eng.Apply("NIF-DATA-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-002"), "special");
    BOOST_CHECK(eng.bit_of("NIF-DATA-002"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "TOKEN");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-002"), "special");
    BOOST_CHECK(eng.bit_of("NIF-DATA-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-DATA-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_DATA_003)
{
    modelnet::Grp03 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-DATA-003", "", "c3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUNDARY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-003"));
    BOOST_CHECK(eng.Apply("NIF-DATA-003", "", "c3a9", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-003"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-003"), "c3a9");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-003"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-003", "", "c3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUNDARY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-003"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-003"), "c3a9");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-DATA-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

