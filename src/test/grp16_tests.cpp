// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp16/grp16.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp16& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp16_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_ASR_RES_001)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-RES-001", "", "planner", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-RES-001"));
    BOOST_CHECK(!eng.Apply("ASR-RES-001", "", "planner", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001#planner"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-RES-001", "", "planner", "", static_cast<int64_t>(0), static_cast<int64_t>(60), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-001"), "planner");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001#planner"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-001#planner"), "planner");
    BOOST_CHECK(!eng.bit_of("ASR-RES-001"));
    BOOST_CHECK(!eng.Apply("ASR-RES-001", "", "planner", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-001"), "planner");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001#planner"), static_cast<int64_t>(60));
    BOOST_CHECK(!eng.Apply("ASR-RES-001", "", "loader", "", static_cast<int64_t>(0), static_cast<int64_t>(41), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001"), static_cast<int64_t>(60));
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001#loader"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-001"), "planner");
    BOOST_CHECK(eng.Apply("ASR-RES-001", "", "loader", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-001"), "loader");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001#loader"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-001#loader"), "loader");
    BOOST_CHECK(!eng.Apply("ASR-RES-001", "", "kv", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-001#kv"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("ASR-RES-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_RES_002)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-RES-002", "", "fair", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BACKPRESSURE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-RES-002"));
    BOOST_CHECK(!eng.Apply("ASR-RES-002", "", "fair", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "BACKPRESSURE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-RES-002", "", "fair", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-002"), "fair");
    BOOST_CHECK(!eng.bit_of("ASR-RES-002"));
    BOOST_CHECK(!eng.Apply("ASR-RES-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BACKPRESSURE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-002"), "fair");
    BOOST_CHECK(eng.Apply("ASR-RES-002", "", "tight", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-RES-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-RES-002"), "tight");
    BOOST_CHECK_EQUAL(eng.classification("ASR-RES-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_SEC_001)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-SEC-001", "", "org", "org", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOMAIN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-SEC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-SEC-001"));
    BOOST_CHECK(eng.Apply("ASR-SEC-001", "", "org", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-SEC-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-001"), "org");
    BOOST_CHECK(!eng.bit_of("ASR-SEC-001"));
    BOOST_CHECK(!eng.Apply("ASR-SEC-001", "", "org", "org", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOMAIN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-SEC-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-001"), "org");
    BOOST_CHECK_EQUAL(eng.classification("ASR-SEC-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_SEC_002)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-SEC-002", "", "secret", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-SEC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-SEC-002"));
    BOOST_CHECK(eng.Apply("ASR-SEC-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-SEC-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-002"), "local");
    BOOST_CHECK(!eng.bit_of("ASR-SEC-002"));
    BOOST_CHECK(!eng.Apply("ASR-SEC-002", "", "secret", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-SEC-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-002"), "local");
    BOOST_CHECK_EQUAL(eng.classification("ASR-SEC-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_TRN_001)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-TRN-001", "", "alice", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONTRIBUTOR");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-001"));
    BOOST_CHECK(!eng.Apply("ASR-TRN-001", "", "alice", "alice", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONTRIBUTOR");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-001"), "");
    BOOST_CHECK(eng.Apply("ASR-TRN-001", "", "alice", "bob", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-001"), "alice,bob");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-001"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-TRN-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_TRN_002)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-TRN-002", "", "full", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-002"));
    BOOST_CHECK(eng.Apply("ASR-TRN-002", "", "full", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-002"), "full");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-002"));
    BOOST_CHECK(!eng.Apply("ASR-TRN-002", "", "partial", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-002"), "full");
    BOOST_CHECK_EQUAL(eng.classification("ASR-TRN-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_TRN_003)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-TRN-003", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-003"));
    BOOST_CHECK(!eng.Apply("ASR-TRN-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "INFLUENCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-003"), "");
    BOOST_CHECK(eng.Apply("ASR-TRN-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-003"), "");
    BOOST_CHECK(eng.Apply("ASR-TRN-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-003"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-003"), "local");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-003"));
    BOOST_CHECK(eng.Apply("ASR-TRN-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-003"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-003"), "local");
    BOOST_CHECK(!eng.Apply("ASR-TRN-003", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-003"), static_cast<int64_t>(40));
    BOOST_CHECK(!eng.Apply("ASR-TRN-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "INFLUENCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-003"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-003"), "local");
    BOOST_CHECK_EQUAL(eng.classification("ASR-TRN-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_TRN_004)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-TRN-004", "", "private_prompt", "v1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-004"));
    BOOST_CHECK(!eng.Apply("ASR-TRN-004", "", "public_trajectory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-004"), "");
    BOOST_CHECK(eng.Apply("ASR-TRN-004", "", "public_trajectory", "v1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-004"), "public_trajectory");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-004"));
    BOOST_CHECK(eng.Apply("ASR-TRN-004", "", "synthetic_trajectory", "v2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-004"), "synthetic_trajectory");
    BOOST_CHECK_EQUAL(eng.classification("ASR-TRN-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_TRN_005)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-TRN-005", "", "fork", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-005"));
    BOOST_CHECK(eng.Apply("ASR-TRN-005", "", "fork", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-005"), "fork");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-005"));
    BOOST_CHECK(!eng.Apply("ASR-TRN-005", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-TRN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-TRN-005"), "fork");
    BOOST_CHECK(!eng.bit_of("ASR-TRN-005"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-TRN-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_VAL_001)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-VAL-001", "score", "metric", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-001"));
    BOOST_CHECK(eng.Apply("ASR-VAL-001", "commit", "suite", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-001"), "");
    BOOST_CHECK(eng.Apply("ASR-VAL-001", "score", "metric", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-001"), "metric");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-001"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-VAL-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_VAL_002)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-VAL-002", "", "trial", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-002"));
    BOOST_CHECK(eng.Apply("ASR-VAL-002", "", "trial", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-002"), "trial");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-VAL-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_VAL_003)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-VAL-003", "", "author", "author", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-003"));
    BOOST_CHECK(eng.Apply("ASR-VAL-003", "", "author", "reviewer", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-003"), "author");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-003"));
    BOOST_CHECK(!eng.Apply("ASR-VAL-003", "", "author", "author", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-003"), "author");
    BOOST_CHECK_EQUAL(eng.classification("ASR-VAL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_VAL_004)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-VAL-004", "promote", "cert", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-004"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-VAL-004", "adopt", "weights", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-004"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("ASR-VAL-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_VAL_005)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-VAL-005", "", "cycle", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-005"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("ASR-VAL-005", "", "cycle", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-VAL-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-VAL-005"), "cycle");
    BOOST_CHECK(!eng.bit_of("ASR-VAL-005"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("ASR-VAL-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_ACT_001)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-ACT-001", "", "shell", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EFFECT");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-ACT-001"));
    BOOST_CHECK(eng.Apply("DS-ACT-001", "", "D0", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-001"), "D0");
    BOOST_CHECK(eng.Apply("DS-ACT-001", "", "D1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-001"), "D1");
    BOOST_CHECK(eng.Apply("DS-ACT-001", "", "D2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-001"), "D2");
    BOOST_CHECK(eng.Apply("DS-ACT-001", "", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-001"), "D3");
    BOOST_CHECK(eng.Apply("DS-ACT-001", "", "D4", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-001"), "D4");
    BOOST_CHECK(!eng.bit_of("DS-ACT-001"));
    BOOST_CHECK(!eng.Apply("DS-ACT-001", "", "D5", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EFFECT");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-001"), "D4");
    BOOST_CHECK_EQUAL(eng.classification("DS-ACT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp16 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-NO-SUCH", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NO-SUCH"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
