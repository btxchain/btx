// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp01/grp01.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp01& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp01_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_NIF_NAT_001)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "sidecar", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-001"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "btxd", "extra", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FLAG");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-001"));
    BOOST_CHECK(eng.Apply("NIF-NAT-001", "btxd", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-001"), "btxd");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-001"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "btxd", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-001"), "btxd");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-NAT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_NAT_002)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-NAT-002", "grant", "id1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BIND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-002"));
    BOOST_CHECK(eng.Apply("NIF-NAT-002", "grant", "id1", "art|journal", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-002"), "id1");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-002"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-002", "grant", "id1", "art|journal", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-002"), "id1");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-NAT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_NAT_003)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-NAT-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-003"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-003", "", "req1", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-003"));
    BOOST_CHECK(eng.Apply("NIF-NAT-003", "", "req1", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-003"), "req1");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-003"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-003", "", "req2", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-003"), "req1");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-NAT-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_NAT_004)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-NAT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-004"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-004"));
    BOOST_CHECK(eng.Apply("NIF-NAT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-004"), "reserved");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-004"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-004"), "reserved");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-NAT-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_NAT_005)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-NAT-005", "other", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "WORKER");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-005"));
    BOOST_CHECK(eng.Apply("NIF-NAT-005", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-005"), "ok");
    BOOST_CHECK(eng.bit_of("NIF-NAT-005"));
    BOOST_CHECK(eng.Apply("NIF-NAT-005", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-005"), "ok");
    BOOST_CHECK(eng.bit_of("NIF-NAT-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-NAT-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_NAT_006)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-NAT-006", "node", "release", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-006"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-006", "", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-006"));
    BOOST_CHECK(eng.Apply("NIF-NAT-006", "node", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-006"), "node");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-006"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-006", "node", "component", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-006"), "node");
    BOOST_CHECK(!eng.bit_of("NIF-NAT-006"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-NAT-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_FORK_001)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-FORK-001", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PIN");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-001"));
    BOOST_CHECK(eng.Apply("NIF-FORK-001", "", "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-001"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-001"), "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-001"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-001", "", "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-001"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-001"), "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-FORK-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_FORK_002)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-FORK-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-002"));
    BOOST_CHECK(eng.Apply("NIF-FORK-002", "", "MIT", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-002"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-002"), "MIT");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-002"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-002", "", "Apache", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-002"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-002"), "MIT");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-FORK-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_FORK_003)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-FORK-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-003"));
    BOOST_CHECK(eng.Apply("NIF-FORK-003", "", "gen1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-003"), "gen1");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-003"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-003", "", "gen2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-003"), "gen1");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-FORK-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_FORK_004)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-FORK-004", "", "step", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-004"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-004", "", "step", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-FORK-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_FORK_005)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-FORK-005", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-005"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-005", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BATCH");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-005"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-005", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-005"));
    BOOST_CHECK(eng.Apply("NIF-FORK-005", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-005"), "local");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-FORK-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_FORK_006)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-FORK-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DELTA");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-006"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-006", "apply", "d1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UPGRADE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-006"));
    BOOST_CHECK(eng.Apply("NIF-FORK-006", "", "d1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-006"), "d1");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-006"));
    BOOST_CHECK(!eng.Apply("NIF-FORK-006", "", "d2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-FORK-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-FORK-006"), "d1");
    BOOST_CHECK(!eng.bit_of("NIF-FORK-006"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-FORK-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PROF_001)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PROF-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PLATFORM");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-001"));
    BOOST_CHECK(eng.Apply("NIF-PROF-001", "", "linux", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-001"), "linux");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-001"));
    BOOST_CHECK(!eng.Apply("NIF-PROF-001", "", "windows", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-001"), "linux");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PROF-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PROF_002)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PROF-002", "", "deepseek-v4.1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "V41");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-002"));
    BOOST_CHECK(!eng.Apply("NIF-PROF-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-002"));
    BOOST_CHECK(eng.Apply("NIF-PROF-002", "", "dense_gqa_v1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-002"), "dense_gqa_v1");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PROF-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PROF_003)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PROF-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOMAIN");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-003"));
    BOOST_CHECK(eng.Apply("NIF-PROF-003", "", "cpu-fp32", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-003"), "cpu-fp32");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-003"));
    BOOST_CHECK(!eng.Apply("NIF-PROF-003", "", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-003"), "cpu-fp32");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PROF-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PROF_004)
{
    modelnet::Grp01 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PROF-004", "ab", "hardware", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-004"));
    BOOST_CHECK(!eng.Apply("NIF-PROF-004", "abc", "throughput", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-004"));
    BOOST_CHECK(eng.Apply("NIF-PROF-004", "aa", "throughput", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-004"), "aa");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-004"));
    BOOST_CHECK(eng.Apply("NIF-PROF-004", "bb", "approximate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-004"), "aa");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PROF-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

