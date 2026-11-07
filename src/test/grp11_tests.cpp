// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp11/grp11.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp11& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp11_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_ASR_ACC_001)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "PARTICIPANTS");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-ACC-001"));
    BOOST_CHECK(!eng.Apply("ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "PARTICIPANTS");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-ACC-001"));
    BOOST_CHECK(eng.Apply("ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-001"), "pair");
    BOOST_CHECK(!eng.bit_of("ASR-ACC-001"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-001"), "pair");
    BOOST_CHECK(!eng.bit_of("ASR-ACC-001"));
    BOOST_CHECK(!eng.Apply("ASR-ACC-001", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARTICIPANTS");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-001"), "pair");
    BOOST_CHECK(!eng.Apply("ASR-ACC-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-001"), "pair");
    BOOST_CHECK_EQUAL(eng.classification("ASR-ACC-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_ACC_002)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-ACC-002", "pass", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-ACC-002"));
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-ACC-002", "pass", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ACC-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.bit_of("ASR-ACC-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-ACC-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_ART_001)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-ART-001", "", "closed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-ART-001"));
    BOOST_CHECK(!eng.Apply("ASR-ART-001", "", "closed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-ART-001", "", "closed", "root", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-001"), "");
    BOOST_CHECK(eng.Apply("ASR-ART-001", "", "closed", "root", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-001"), "closed");
    BOOST_CHECK(!eng.bit_of("ASR-ART-001"));
    BOOST_CHECK(!eng.Apply("ASR-ART-001", "", "next", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-001"), "closed");
    BOOST_CHECK_EQUAL(eng.classification("ASR-ART-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_ART_002)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-ART-002"));
    BOOST_CHECK(!eng.Apply("ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK(!eng.Apply("ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(65), false, err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-ART-002", "", "lo", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-002"), "lo");
    BOOST_CHECK(!eng.bit_of("ASR-ART-002"));
    BOOST_CHECK(!eng.Apply("ASR-ART-002", "", "hi", "", static_cast<int64_t>(0), static_cast<int64_t>(64), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-002"), "lo");
    modelnet::Grp11 top;
    BOOST_CHECK(top.Apply("ASR-ART-002", "", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(64), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(top.stored("ASR-ART-002"), static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(top.text_of("ASR-ART-002"), "top");
    BOOST_CHECK(!top.Apply("ASR-ART-002", "", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(65), false, err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK_EQUAL(top.stored("ASR-ART-002"), static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(top.text_of("ASR-ART-002"), "top");
    BOOST_CHECK_EQUAL(eng.classification("ASR-ART-002"), "COMPONENT");
    BOOST_CHECK_EQUAL(top.classification("ASR-ART-002"), "COMPONENT");
    Idle(eng);
    Idle(top);
}

BOOST_AUTO_TEST_CASE(req_ASR_ART_003)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-ART-003"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(4194305), false, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-ART-003", "", "piece", "", static_cast<int64_t>(0), static_cast<int64_t>(4194304), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-003"), static_cast<int64_t>(4194304));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-003"), "piece");
    BOOST_CHECK(!eng.bit_of("ASR-ART-003"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-ART-003", "", "again", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-003"), static_cast<int64_t>(4194304));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-003"), "piece");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    modelnet::Grp11 one;
    BOOST_CHECK(one.Apply("ASR-ART-003", "", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(one.stored("ASR-ART-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(one.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("ASR-ART-003"), "COMPONENT");
    BOOST_CHECK_EQUAL(one.classification("ASR-ART-003"), "COMPONENT");
    Idle(eng);
    Idle(one);
}

BOOST_AUTO_TEST_CASE(req_ASR_ART_004)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-ART-004", "", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-004"), "gen-a");
    BOOST_CHECK(!eng.bit_of("ASR-ART-004"));
    BOOST_CHECK(!eng.Apply("ASR-ART-004", "", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-004"), "gen-a");
    BOOST_CHECK(!eng.bit_of("ASR-ART-004"));
    BOOST_CHECK(!eng.Apply("ASR-ART-004", "", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-004"), "gen-a");
    BOOST_CHECK(!eng.bit_of("ASR-ART-004"));
    BOOST_CHECK(!eng.Apply("ASR-ART-004", "", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-004"), "gen-a");
    BOOST_CHECK_EQUAL(eng.classification("ASR-ART-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_ART_005)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-ART-005", "", "body-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-ART-005"));
    BOOST_CHECK(!eng.Apply("ASR-ART-005", "", "body-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-005"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-ART-005", "", "body-a", "d1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-005"), "body-a");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-ART-005", "", "body-b", "d2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-ART-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ART-005"), "body-a");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("ASR-ART-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_CAP_001)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "", "shell", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INTERPRETER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-CAP-001"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "", "shell", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INTERPRETER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INTERPRETER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-001"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-CAP-001", "", "none", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-001"), "none");
    BOOST_CHECK(!eng.bit_of("ASR-CAP-001"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "", "none", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-001"), "none");
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "", "python", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INTERPRETER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-001"), "none");
    BOOST_CHECK_EQUAL(eng.classification("ASR-CAP-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_CAP_002)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-CAP-002"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-002"), "env-a");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-CAP-002", "", "env-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-002"), "env-a");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-CAP-002", "", "env-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-002"), "env-a");
    BOOST_CHECK_EQUAL(eng.classification("ASR-CAP-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_CAP_003)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-CAP-003", "", "model-a", "model-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-CAP-003"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-003", "", "model-a", "model-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-CAP-003", "", "model-a", "pkg-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-003"), "model-a");
    BOOST_CHECK(!eng.Apply("ASR-CAP-003", "", "model-c", "pkg-d", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-003"), "model-a");
    BOOST_CHECK(!eng.Apply("ASR-CAP-003", "", "model-a", "model-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-003"), "model-a");
    BOOST_CHECK_EQUAL(eng.classification("ASR-CAP-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_CAP_004)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-CAP-004", "", "sandbox/job", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-CAP-004"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-004", "", "sandbox/job", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-CAP-004", "", "job/sandbox", "sandbox/", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-004"), "");
    BOOST_CHECK(eng.Apply("ASR-CAP-004", "", "sandbox/job", "sandbox/", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-CAP-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-004"), "sandbox/job");
    BOOST_CHECK(!eng.bit_of("ASR-CAP-004"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-004", "", "sandbox/next", "sandbox/", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-004"), "sandbox/job");
    BOOST_CHECK(!eng.Apply("ASR-CAP-004", "", "a", "ab", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-CAP-004"), "sandbox/job");
    BOOST_CHECK_EQUAL(eng.classification("ASR-CAP-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVD_001)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVD-001", "", "private-trace", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-001"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-001", "", "private-trace", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-001"), "");
    BOOST_CHECK(eng.Apply("ASR-EVD-001", "", "public-trace", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-001"), "public-trace");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-001"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-001", "", "has private bit", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-001"), "public-trace");
    BOOST_CHECK(!eng.Apply("ASR-EVD-001", "", "second-public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-001"), "public-trace");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVD-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVD_002)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVD-002", "", "summary-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SOURCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-002"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-002", "", "summary-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SOURCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-EVD-002", "", "summary-a", "src-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-002"), "summary-a");
    BOOST_CHECK(!eng.Apply("ASR-EVD-002", "", "summary-b", "src-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-002"), "summary-a");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVD-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVD_003)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVD-003", "", "note ignore previous end", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INJECTION");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-003"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-003", "", "note ignore previous end", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "INJECTION");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.bit_of("ASR-EVD-003"));
    BOOST_CHECK(eng.Apply("ASR-EVD-003", "", "ordinary note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-003"), "ordinary note");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-003"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-003", "", "second note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-003"), "ordinary note");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-003"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVD-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVD_004)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-004"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-004"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-004"), "released");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-004"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-004", "", "later", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-004"), "released");
    BOOST_CHECK(!eng.Apply("ASR-EVD-004", "", "released", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-004"), "released");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVD-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVD_005)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVD-005", "retrieve", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-005"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-005", "retrieve", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-005"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.bit_of("ASR-EVD-005"));
    BOOST_CHECK(eng.Apply("ASR-EVD-005", "promise", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-005"), "sig-a");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-005"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-005", "retrieve", "sig-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-005"), "sig-a");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-005"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-005", "promise", "sig-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-005"), "sig-a");
    BOOST_CHECK(!eng.bit_of("ASR-EVD-005"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVD-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp11 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK(!eng.bit_of(""));
    BOOST_CHECK_EQUAL(eng.classification(""), "COMPONENT");
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-NONE", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NONE"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NONE"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NONE"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NONE"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
