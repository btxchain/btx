// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp13/grp13.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp13& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp13_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_ASR_HND_001)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-HND-001", "", "beta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GRANT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-HND-001"));
    BOOST_CHECK(eng.Apply("ASR-HND-001", "", "beta", "alpha", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-001"), "alpha");
    BOOST_CHECK(!eng.bit_of("ASR-HND-001"));
    BOOST_CHECK(!eng.Apply("ASR-HND-001", "", "beta", "gamma", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-001"), "alpha");
    BOOST_CHECK(!eng.bit_of("ASR-HND-001"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-HND-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_HND_002)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-HND-002", "", "fence-ok", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FENCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-HND-002"));
    BOOST_CHECK(eng.Apply("ASR-HND-002", "", "fence-ok", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-002"), "fence-ok");
    BOOST_CHECK(!eng.bit_of("ASR-HND-002"));
    BOOST_CHECK(!eng.Apply("ASR-HND-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-002"), "fence-ok");
    BOOST_CHECK_EQUAL(eng.classification("ASR-HND-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_HND_003)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-HND-003", "", "cross", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-HND-003"));
    BOOST_CHECK(!eng.Apply("ASR-HND-003", "", "crossroad", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK(!eng.bit_of("ASR-HND-003"));
    BOOST_CHECK(eng.Apply("ASR-HND-003", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-003"), "plain");
    BOOST_CHECK(!eng.bit_of("ASR-HND-003"));
    BOOST_CHECK(!eng.Apply("ASR-HND-003", "", "cross", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-003"), "plain");
    BOOST_CHECK(!eng.bit_of("ASR-HND-003"));
    BOOST_CHECK(!eng.Apply("ASR-HND-003", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-003"), "plain");
    BOOST_CHECK(!eng.bit_of("ASR-HND-003"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-HND-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_HND_004)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-HND-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "USEFUL");
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-HND-004"));
    BOOST_CHECK(eng.Apply("ASR-HND-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-HND-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-004"), "note");
    BOOST_CHECK(!eng.bit_of("ASR-HND-004"));
    BOOST_CHECK(!eng.Apply("ASR-HND-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-004"), "note");
    BOOST_CHECK_EQUAL(eng.classification("ASR-HND-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_KVC_001)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-KVC-001", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-001"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-001", "", "a,b,c,d,e", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-001"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-KVC-001", "", "a,b,c,d", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-001"), "a,b,c,d");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-001"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-001", "", "w,x,y,z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-001"), "a,b,c,d");
    BOOST_CHECK_EQUAL(eng.classification("ASR-KVC-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_KVC_002)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-KVC-002", "", "pre", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "SUFFIX");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-002"));
    BOOST_CHECK(eng.Apply("ASR-KVC-002", "", "pre", "suf", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-002"), "pre");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-002"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-002", "", "pre", "suf", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-002"), "pre");
    BOOST_CHECK(!eng.Apply("ASR-KVC-002", "", "pre2", "suf", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-002"), "pre");
    BOOST_CHECK(eng.bit_of("ASR-KVC-002"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-002", "", "pre2", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "SUFFIX");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-002"), "pre");
    BOOST_CHECK(eng.bit_of("ASR-KVC-002"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-002", "", "pre", "suf", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-002"), "pre");
    BOOST_CHECK(eng.bit_of("ASR-KVC-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-KVC-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_KVC_003)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-KVC-003", "", "nixl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-003"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-KVC-003", "", "mooncake", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-KVC-003", "", "rdma", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-KVC-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-KVC-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(12), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-003"), static_cast<int64_t>(12));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-003"), "local");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-003"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-KVC-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-003"), static_cast<int64_t>(12));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-KVC-003", "", "nixl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-003"), static_cast<int64_t>(12));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("ASR-KVC-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_KVC_004)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-KVC-004", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-004"));
    BOOST_CHECK(eng.Apply("ASR-KVC-004", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-004"), "abc");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-004"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-004", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-004"));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-004"), "abc");
    BOOST_CHECK(!eng.Apply("ASR-KVC-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-004"), "abc");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-004"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-KVC-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_KVC_005)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-005"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-KVC-005", "revoke", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-005"), "prefetch");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-005"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-005"), "prefetch");
    BOOST_CHECK(eng.Apply("ASR-KVC-005", "revoke", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-005"), "revoke");
    BOOST_CHECK(!eng.Apply("ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-005"), "revoke");
    BOOST_CHECK(!eng.Apply("ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-005"), "revoke");
    BOOST_CHECK(!eng.Apply("ASR-KVC-005", "revoke", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-005"), "revoke");
    BOOST_CHECK_EQUAL(eng.classification("ASR-KVC-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_KVC_006)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-KVC-006", "", "measured", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-006"), "");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-006"));
    BOOST_CHECK(eng.Apply("ASR-KVC-006", "", "measured", "x", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-KVC-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-006"), "measured");
    BOOST_CHECK(!eng.bit_of("ASR-KVC-006"));
    BOOST_CHECK(!eng.Apply("ASR-KVC-006", "", "other", "y", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-KVC-006"), "measured");
    BOOST_CHECK_EQUAL(eng.classification("ASR-KVC-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_MIG_001)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-MIG-001", "", "skip", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ASSURANCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-MIG-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-MIG-001"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("ASR-MIG-001", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-MIG-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-001"), "kept");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-MIG-001", "", "skip", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ASSURANCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-MIG-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-001"), "kept");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-MIG-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-001"), "kept");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("ASR-MIG-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_MIG_002)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-MIG-002", "", "page", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("ASR-MIG-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-MIG-002"));
    BOOST_CHECK(eng.Apply("ASR-MIG-002", "", "page", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-MIG-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-002"), "page");
    BOOST_CHECK(!eng.Apply("ASR-MIG-002", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("ASR-MIG-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-002"), "page");
    BOOST_CHECK(!eng.Apply("ASR-MIG-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-002"), "page");
    BOOST_CHECK_EQUAL(eng.classification("ASR-MIG-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NAT_001)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NAT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-001"));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.Apply("ASR-NAT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.Apply("ASR-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "SPAWN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-001"), "");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(eng.Apply("ASR-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-001"), "btxd");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-001"));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.Apply("ASR-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-001"), "btxd");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.classification("ASR-NAT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NAT_002)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-NAT-002", "mark", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-002"), static_cast<int64_t>(11));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-002"), "row");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-002"));
    BOOST_CHECK(eng.Apply("ASR-NAT-002", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-002"), static_cast<int64_t>(11));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-002"), "row");
    BOOST_CHECK(eng.bit_of("ASR-NAT-002"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-002", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-002"), static_cast<int64_t>(11));
    BOOST_CHECK(eng.bit_of("ASR-NAT-002"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-002", "mark", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-002"), static_cast<int64_t>(11));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-002"), "row");
    BOOST_CHECK(eng.bit_of("ASR-NAT-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NAT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NAT_003)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NAT-003", "", "zero", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-003"));
    BOOST_CHECK(eng.Apply("ASR-NAT-003", "", "zero", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-003"), "zero");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-003"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-003", "", "five", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-003"), "zero");
    modelnet::Grp13 eng_pos;
    BOOST_CHECK(eng_pos.Apply("ASR-NAT-003", "", "six", "", static_cast<int64_t>(0), static_cast<int64_t>(6), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng_pos.stored("ASR-NAT-003"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng_pos.text_of("ASR-NAT-003"), "six");
    BOOST_CHECK_EQUAL(eng_pos.classification("ASR-NAT-003"), "COMPONENT");
    BOOST_CHECK_EQUAL(eng.classification("ASR-NAT-003"), "COMPONENT");
    Idle(eng);
    Idle(eng_pos);
}

BOOST_AUTO_TEST_CASE(req_ASR_NAT_004)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NAT-004", "", "wallet", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "WALLET");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-004"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-004", "", "disk", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RESOURCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-004"), "");
    BOOST_CHECK(!eng.Apply("ASR-NAT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RESOURCE");
    BOOST_CHECK(eng.Apply("ASR-NAT-004", "", "cpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-004"), "cpu");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-004"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-004", "", "memory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-004"), "cpu");
    modelnet::Grp13 eng_mem;
    BOOST_CHECK(eng_mem.Apply("ASR-NAT-004", "", "memory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng_mem.stored("ASR-NAT-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng_mem.text_of("ASR-NAT-004"), "memory");
    BOOST_CHECK(!eng_mem.bit_of("ASR-NAT-004"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NAT-004"), "COMPONENT");
    BOOST_CHECK_EQUAL(eng_mem.classification("ASR-NAT-004"), "COMPONENT");
    Idle(eng);
    Idle(eng_mem);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp13 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification(""), "COMPONENT");
    BOOST_CHECK(!eng.Apply("ASR-NONE", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NONE"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NONE"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NONE"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NONE"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
