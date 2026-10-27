// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp02/grp02.h>
#include <test/util/setup_common.h>

#include <modelnet/identity.h>
#include <util/strencodings.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp02& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp02_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_NIF_PROF_005)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PROF-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, err));
    BOOST_CHECK_EQUAL(err, "SEMANTIC");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-005"));
    BOOST_CHECK(eng.Apply("NIF-PROF-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-005"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-005"), "8,2,2");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PROF-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_PROF_006)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-PROF-006", "", "", "", static_cast<int64_t>(10), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-006"));
    BOOST_CHECK(!eng.Apply("NIF-PROF-006", "", "", "", static_cast<int64_t>(50), static_cast<int64_t>(60), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-006"));
    BOOST_CHECK(eng.Apply("NIF-PROF-006", "", "", "", static_cast<int64_t>(10), static_cast<int64_t>(60), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-006"), static_cast<int64_t>(70));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-006"), "60+10");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-006"));
    BOOST_CHECK(!eng.Apply("NIF-PROF-006", "release", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-006"), static_cast<int64_t>(70));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-006"), "60+10");
    BOOST_CHECK(!eng.bit_of("NIF-PROF-006"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-PROF-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_EXEC_001)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-EXEC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-001"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-001", "s0", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "CHUNK");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-001"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-001", "s0", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-001"), "s0");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-001"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-001", "s1", "c2", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-001"), "s0");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-001"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-001", "s0", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-001"), "s0");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-EXEC-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_EXEC_002)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PIPE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-002"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4097), false, err));
    BOOST_CHECK_EQUAL(err, "PIPE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-002"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(128), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-002"), static_cast<int64_t>(128));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-002"), "pipe");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-002"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(64), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-002"), static_cast<int64_t>(128));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-002"), "pipe");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-EXEC-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_EXEC_003)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("NIF-EXEC-003", "hold", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-003"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-003"), "held");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-003"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-003", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-003"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-003"), "held");
    BOOST_CHECK(eng.bit_of("NIF-EXEC-003"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-003", "release", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-003"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-003"), "held");
    BOOST_CHECK(eng.bit_of("NIF-EXEC-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-EXEC-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_EXEC_004)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-EXEC-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-004"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-004", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-004"), "a,b");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-004"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-004", "", "a,c", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ALTERED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-004"), "a,b");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-004"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-004", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-004"), "a,b");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-EXEC-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_EXEC_005)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-EXEC-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DEADLINE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-005"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-005", "open", "", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-005"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-005"), "open");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-005"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-005", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-005"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-005"), "open");
    BOOST_CHECK(eng.bit_of("NIF-EXEC-005"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-005", "drain", "", "", static_cast<int64_t>(10), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-005"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-005"), "open");
    BOOST_CHECK(eng.bit_of("NIF-EXEC-005"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-005", "drain", "", "", static_cast<int64_t>(9), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-005"), "drained");
    BOOST_CHECK(eng.bit_of("NIF-EXEC-005"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-005", "drain", "", "", static_cast<int64_t>(9), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-005"), "drained");
    BOOST_CHECK(eng.bit_of("NIF-EXEC-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-EXEC-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_EXEC_006)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-EXEC-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GRAMMAR");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-006"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1025), false, err));
    BOOST_CHECK_EQUAL(err, "GRAMMAR");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-006"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-006", "grammar", "", "", static_cast<int64_t>(0), static_cast<int64_t>(32), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-006"), static_cast<int64_t>(32));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-006"), "grammar");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-006"));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-006", "tool", "search", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-006"), static_cast<int64_t>(32));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-006"), "grammar");
    BOOST_CHECK(!eng.bit_of("NIF-EXEC-006"));
    BOOST_CHECK(eng.Apply("NIF-EXEC-006", "tool", "search", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-006"), static_cast<int64_t>(32));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-006"), "grammar");
    BOOST_CHECK(eng.bit_of("NIF-EXEC-006"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-EXEC-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_KV_001)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-001", "rt", "model", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "COMPONENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-001"));
    BOOST_CHECK(eng.Apply("NIF-KV-001", "rt", "model", "tenant|gen", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-001"), "model");
    BOOST_CHECK(!eng.bit_of("NIF-KV-001"));
    BOOST_CHECK(!eng.Apply("NIF-KV-001", "rt", "model", "tenant|gen", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-001"), "model");
    BOOST_CHECK(!eng.bit_of("NIF-KV-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-KV-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_KV_003)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "COMPONENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-003"));
    BOOST_CHECK(eng.Apply("NIF-KV-003", "r1", "m1", "t1", static_cast<int64_t>(1), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-003"), "m1|r1|t1|1");
    BOOST_CHECK(!eng.bit_of("NIF-KV-003"));
    BOOST_CHECK(!eng.Apply("NIF-KV-003", "r1", "m1", "t1", static_cast<int64_t>(2), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-003"), "m1|r1|t1|1");
    BOOST_CHECK(!eng.bit_of("NIF-KV-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-KV-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_KV_004)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-004"));
    BOOST_CHECK(!eng.Apply("NIF-KV-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-004"));
    BOOST_CHECK(eng.Apply("NIF-KV-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-004"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-004"), "local");
    BOOST_CHECK(!eng.bit_of("NIF-KV-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-KV-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_KV_005)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-005", "", "alloc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-005"));
    BOOST_CHECK(!eng.Apply("NIF-KV-005", "", "bind", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-KV-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_KV_006)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-006", "submit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-006"));
    BOOST_CHECK(eng.Apply("NIF-KV-006", "submit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-006"), "rank");
    BOOST_CHECK(!eng.bit_of("NIF-KV-006"));
    BOOST_CHECK(!eng.Apply("NIF-KV-006", "restore", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-006"), "rank");
    BOOST_CHECK(!eng.bit_of("NIF-KV-006"));
    BOOST_CHECK(eng.Apply("NIF-KV-006", "submit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-006"), "rank");
    BOOST_CHECK(!eng.bit_of("NIF-KV-006"));
    BOOST_CHECK(eng.Apply("NIF-KV-006", "restore", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-006"), "restored");
    BOOST_CHECK(!eng.bit_of("NIF-KV-006"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-KV-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_KV_008)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1025), false, err));
    BOOST_CHECK_EQUAL(err, "MEMORY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-008"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-008"));
    BOOST_CHECK(!eng.Apply("NIF-KV-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-008"), "");
    BOOST_CHECK(!eng.bit_of("NIF-KV-008"));
    BOOST_CHECK(eng.Apply("NIF-KV-008", "", "g1", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-008"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-008"), "g1");
    BOOST_CHECK(!eng.bit_of("NIF-KV-008"));
    BOOST_CHECK(!eng.Apply("NIF-KV-008", "", "g2", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-008"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-008"), "g1");
    BOOST_CHECK(!eng.bit_of("NIF-KV-008"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-KV-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_003)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-LAN-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-003"));
    BOOST_CHECK(!eng.Apply("NIF-LAN-003", "", "peer-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-003"), "peer-a");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-003"));
    BOOST_CHECK(!eng.Apply("NIF-LAN-003", "zz", "peer-a", "zz", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-003"), "peer-a");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_003_signature)
{
    std::vector<unsigned char> pk, sk, sig;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const std::string peer = "peer-a";
    const Span<const unsigned char> msg(reinterpret_cast<const unsigned char*>(peer.data()), peer.size());
    BOOST_REQUIRE(modelnet::SignMlDsa44(Span<const unsigned char>(sk.data(), sk.size()), msg, sig, err));
    modelnet::Grp02 eng;
    BOOST_CHECK(eng.Apply("NIF-LAN-003", HexStr(pk), peer, HexStr(sig), static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.bit_of("NIF-LAN-003"));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-003"), peer);
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("NIF-LAN-003", HexStr(pk), peer, HexStr(sig), static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(req_NIF_LAN_004)
{
    modelnet::Grp02 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-LAN-004", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-004"));
    BOOST_CHECK(eng.Apply("NIF-LAN-004", "", "lan", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-004"), "lan");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-004"));
    BOOST_CHECK(!eng.Apply("NIF-LAN-004", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-004"), "lan");
    BOOST_CHECK(!eng.bit_of("NIF-LAN-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-LAN-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

