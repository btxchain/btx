// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp12/grp12.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp12& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp12_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK(!eng.bit_of(""));
    BOOST_CHECK(!eng.Apply("ASR-EVO-000", "", "delta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-000"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-000"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-000"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVO-000"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVO_001)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVO-001", "", "delta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNVERIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-001"));
    BOOST_CHECK(eng.Apply("ASR-EVO-001", "", "delta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-001"), "delta");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-001"));
    BOOST_CHECK(!eng.Apply("ASR-EVO-001", "", "delta", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-001"), "delta");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-001"));
    BOOST_CHECK(!eng.Apply("ASR-EVO-001", "", "delta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNVERIFIED");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-001"), "delta");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVO-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVO_002)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-002"));
    BOOST_CHECK(!eng.Apply("ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-002"), "niche");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-002"));
    BOOST_CHECK(!eng.Apply("ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-002"), "niche");
    modelnet::Grp12 wide;
    BOOST_CHECK(wide.Apply("ASR-EVO-002", "", "wide", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(wide.stored("ASR-EVO-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(wide.text_of("ASR-EVO-002"), "niche");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVO-002"), "COMPONENT");
    Idle(eng);
    Idle(wide);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVO_003)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVO-003", "", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BASELINE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-003"));
    BOOST_CHECK(eng.Apply("ASR-EVO-003", "", "policy", "base", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-003"), "policy");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-003"));
    BOOST_CHECK(!eng.Apply("ASR-EVO-003", "", "policy", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-003"), "policy");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVO-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EVO_004)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EVO-004", "promote", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-004"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("ASR-EVO-004", "shadow", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-004"), "policy");
    BOOST_CHECK(!eng.bit_of("ASR-EVO-004"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("ASR-EVO-004", "promote", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVO-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-004"), "policy");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-EVO-004", "shadow", "policy", "again", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVO-004"), "policy");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EVO-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EXE_001)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EXE-001", "", "", "attempt", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-001"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-001", "", "intent", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-001"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-EXE-001", "", "intent", "attempt", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-001"), "intent|attempt");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-001"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-001", "", "intent", "later", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-001"), "intent|attempt");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EXE_002)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-EXE-002", "", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-002"), "one");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-002"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-002", "", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-002"), "one");
    BOOST_CHECK(!eng.Apply("ASR-EXE-002", "other", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-002"), "one");
    BOOST_CHECK(!eng.Apply("ASR-EXE-002", "", "two", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ALTERED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-002"), "one");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EXE_003)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNKNOWN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-003"));
    BOOST_CHECK(eng.Apply("ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-003"), "once");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-003"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-003"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNKNOWN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-003"), "once");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EXE_004)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EXE-004", "", "lease", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FENCE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-004"));
    BOOST_CHECK(eng.Apply("ASR-EXE-004", "", "lease", "token", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-004"), "token");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-004"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-004", "", "lease", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-004"), "token");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EXE_005)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EXE-005", "", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-005"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-005", "", "lease", "", static_cast<int64_t>(6), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-005"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-EXE-005", "", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-005"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-005"), "lease");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-005"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-005", "", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-005"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.Apply("ASR-EXE-005", "", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-005"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-005"), "lease");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EXE_006)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-006"), "");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-006"));
    BOOST_CHECK(eng.Apply("ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-006"), "seat");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-006"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-006"), "seat");
    BOOST_CHECK(!eng.Apply("ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-006"), "seat");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_EXE_007)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-EXE-007", "", "hold", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-007"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-007"), "hold");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-007"));
    BOOST_CHECK(!eng.Apply("ASR-EXE-007", "", "hold", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-007"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-007"), "hold");
    BOOST_CHECK(!eng.Apply("ASR-EXE-007", "later", "wake", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-007"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-007"), "hold");
    BOOST_CHECK(!eng.bit_of("ASR-EXE-007"));
    modelnet::Grp12 zero;
    BOOST_CHECK(zero.Apply("ASR-EXE-007", "", "zero", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(zero.stored("ASR-EXE-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(zero.text_of("ASR-EXE-007"), "zero");
    BOOST_CHECK(!zero.Apply("ASR-EXE-007", "", "zero", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(zero.stored("ASR-EXE-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(zero.text_of("ASR-EXE-007"), "zero");
    BOOST_CHECK(!zero.Apply("ASR-EXE-007", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(zero.stored("ASR-EXE-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(zero.text_of("ASR-EXE-007"), "zero");
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-007"), "COMPONENT");
    Idle(eng);
    Idle(zero);
}

BOOST_AUTO_TEST_CASE(req_ASR_GRF_001)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-GRF-001", "", "loss", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "VIEW");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-001"));
    BOOST_CHECK(eng.Apply("ASR-GRF-001", "", "dependency", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-001"), "dependency");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-001"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-001", "alt", "dependency", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-001"), "dependency");
    BOOST_CHECK(eng.Apply("ASR-GRF-001", "", "evidence", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-001"), "evidence");
    BOOST_CHECK(eng.Apply("ASR-GRF-001", "", "payment", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-001"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-001"), "payment");
    BOOST_CHECK(eng.Apply("ASR-GRF-001", "", "resource", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-001"), "resource");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-001"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-001", "", "evidence", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-001"), "resource");
    BOOST_CHECK_EQUAL(eng.classification("ASR-GRF-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_GRF_002)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-GRF-002", "", "loop", "loop", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-002"));
    BOOST_CHECK(eng.Apply("ASR-GRF-002", "", "edge", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-002"), "edge");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-002"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-002", "", "edge", "later", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-002"), "edge");
    BOOST_CHECK(!eng.Apply("ASR-GRF-002", "", "loop", "loop", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-002"), "edge");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-002"));
    modelnet::Grp12 blank;
    BOOST_CHECK(blank.Apply("ASR-GRF-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(blank.stored("ASR-GRF-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(blank.text_of("ASR-GRF-002"), "");
    BOOST_CHECK(!blank.bit_of("ASR-GRF-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-GRF-002"), "COMPONENT");
    Idle(eng);
    Idle(blank);
}

BOOST_AUTO_TEST_CASE(req_ASR_GRF_003)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-GRF-003", "", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-003"), "row");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-003"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-003", "", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-003"), "row");
    BOOST_CHECK(eng.Apply("ASR-GRF-003", "retract", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-003"), "row");
    BOOST_CHECK(eng.bit_of("ASR-GRF-003"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-003", "retract", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-003"), static_cast<int64_t>(1));
    BOOST_CHECK(eng.bit_of("ASR-GRF-003"));
    modelnet::Grp12 kept;
    BOOST_CHECK(kept.Apply("ASR-GRF-003", "", "hist", "", static_cast<int64_t>(0), static_cast<int64_t>(6), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(kept.stored("ASR-GRF-003"), static_cast<int64_t>(6));
    BOOST_CHECK(kept.Apply("ASR-GRF-003", "retract", "hist", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(kept.stored("ASR-GRF-003"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(kept.text_of("ASR-GRF-003"), "hist");
    BOOST_CHECK(kept.bit_of("ASR-GRF-003"));
    modelnet::Grp12 first;
    BOOST_CHECK(first.Apply("ASR-GRF-003", "retract", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(first.stored("ASR-GRF-003"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(first.text_of("ASR-GRF-003"), "gone");
    BOOST_CHECK(first.bit_of("ASR-GRF-003"));
    BOOST_CHECK(!first.Apply("ASR-GRF-003", "retract", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(first.stored("ASR-GRF-003"), static_cast<int64_t>(4));
    BOOST_CHECK(first.bit_of("ASR-GRF-003"));
    modelnet::Grp12 neg;
    BOOST_CHECK(neg.Apply("ASR-GRF-003", "", "floor", "", static_cast<int64_t>(0), static_cast<int64_t>(-3), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(neg.stored("ASR-GRF-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(neg.text_of("ASR-GRF-003"), "floor");
    BOOST_CHECK(!neg.bit_of("ASR-GRF-003"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-GRF-003"), "COMPONENT");
    Idle(eng);
    Idle(kept);
    Idle(first);
    Idle(neg);
}

BOOST_AUTO_TEST_CASE(req_ASR_GRF_004)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-GRF-004", "rank", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-004"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-004", "score", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-004"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-GRF-004", "filter", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-004"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-004", "filter", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-004"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-GRF-004", "rank", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-004"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-004"), "top");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-004"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-004", "rank", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-004"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-004"), "top");
    BOOST_CHECK_EQUAL(eng.classification("ASR-GRF-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_GRF_005)
{
    modelnet::Grp12 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-005"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-005"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-005"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-005"), "scope");
    BOOST_CHECK(!eng.bit_of("ASR-GRF-005"));
    BOOST_CHECK(!eng.Apply("ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-GRF-005"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-GRF-005"), "scope");
    modelnet::Grp12 low;
    BOOST_CHECK(low.Apply("ASR-GRF-005", "", "low", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(low.stored("ASR-GRF-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(low.text_of("ASR-GRF-005"), "low");
    BOOST_CHECK(!low.bit_of("ASR-GRF-005"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-GRF-005"), "COMPONENT");
    Idle(eng);
    Idle(low);
}

BOOST_AUTO_TEST_SUITE_END()
