// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp17/grp17.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp17& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp17_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_DS_ACT_002)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-ACT-002", "", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-ACT-002"));
    BOOST_CHECK(eng.Apply("DS-ACT-002", "", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "D3");
    BOOST_CHECK(!eng.bit_of("DS-ACT-002"));
    BOOST_CHECK(!eng.Apply("DS-ACT-002", "", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "D3");
    BOOST_CHECK(!eng.Apply("DS-ACT-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "D3");
    BOOST_CHECK(!eng.Apply("DS-ACT-002", "", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "D3");
    modelnet::Grp17 plain;
    BOOST_CHECK(plain.Apply("DS-ACT-002", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plain.stored("DS-ACT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(plain.text_of("DS-ACT-002"), "plain");
    BOOST_CHECK(!plain.Apply("DS-ACT-002", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(plain.text_of("DS-ACT-002"), "plain");
    BOOST_CHECK_EQUAL(eng.classification("DS-ACT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_ACT_003)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-ACT-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ASSET");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-ACT-003"));
    BOOST_CHECK(!eng.Apply("DS-ACT-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, err));
    BOOST_CHECK_EQUAL(err, "ASSET");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-ACT-003", "", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, err));
    BOOST_CHECK_EQUAL(err, "RADIUS");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-003"), "");
    BOOST_CHECK(!eng.Apply("DS-ACT-003", "", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-ACT-003", "", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-ACT-003", "", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-003"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-003"), "asset");
    BOOST_CHECK(!eng.bit_of("DS-ACT-003"));
    BOOST_CHECK(!eng.Apply("DS-ACT-003", "", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-003"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-003"), "asset");
    BOOST_CHECK(!eng.Apply("DS-ACT-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-003"), "asset");
    BOOST_CHECK_EQUAL(eng.classification("DS-ACT-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_ACT_004)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-ACT-004", "", "effect-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNKNOWN");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-ACT-004"));
    BOOST_CHECK(eng.Apply("DS-ACT-004", "", "effect-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-004"), "effect-a");
    BOOST_CHECK(!eng.bit_of("DS-ACT-004"));
    BOOST_CHECK(!eng.Apply("DS-ACT-004", "", "effect-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNKNOWN");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-004"), "effect-a");
    BOOST_CHECK(!eng.Apply("DS-ACT-004", "", "effect-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ALTERED");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-004"), "effect-a");
    BOOST_CHECK(!eng.Apply("DS-ACT-004", "", "effect-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-004"), "effect-a");
    BOOST_CHECK_EQUAL(eng.classification("DS-ACT-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_ACT_005)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-ACT-005", "", "live", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CANARY");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-ACT-005"));
    BOOST_CHECK(eng.Apply("DS-ACT-005", "", "live", "witness", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-005"), "live");
    BOOST_CHECK(!eng.bit_of("DS-ACT-005"));
    BOOST_CHECK(!eng.Apply("DS-ACT-005", "", "live", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CANARY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-005"), "live");
    BOOST_CHECK(!eng.Apply("DS-ACT-005", "", "changed", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-005"), "live");
    BOOST_CHECK(eng.Apply("DS-ACT-005", "", "changed", "restore", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-005"), "live");
    BOOST_CHECK(eng.Apply("DS-ACT-005", "", "changed", "restore", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-005"), "live");
    BOOST_CHECK_EQUAL(eng.classification("DS-ACT-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_ACT_006)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-ACT-006", "", "retaliate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-ACT-006"));
    BOOST_CHECK(!eng.Apply("DS-ACT-006", "", "do-not-retaliate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-006"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-ACT-006", "", "preserve", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-006"), "preserve");
    BOOST_CHECK(!eng.bit_of("DS-ACT-006"));
    BOOST_CHECK(!eng.Apply("DS-ACT-006", "", "retaliate-later", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-006"), "preserve");
    BOOST_CHECK(!eng.Apply("DS-ACT-006", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-ACT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-006"), "preserve");
    BOOST_CHECK_EQUAL(eng.classification("DS-ACT-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_AUTH_001)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ASSET");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-001"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ASSET");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "cust", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MANDATE");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-001"), "");
    BOOST_CHECK(eng.Apply("DS-AUTH-001", "", "cust", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-001"), "cust|grant");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-001"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "cust", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-001"), "cust|grant");
    BOOST_CHECK_EQUAL(eng.classification("DS-AUTH-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_AUTH_002)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-AUTH-002", "", "", "gen1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-002"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-002", "", "case", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-AUTH-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK(eng.Apply("DS-AUTH-002", "", "case", "gen1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-002"), "case|gen1");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-002"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-002", "", "other", "gen2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-002"), "case|gen1");
    BOOST_CHECK_EQUAL(eng.classification("DS-AUTH-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_AUTH_003)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-003"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(6), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-003"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-003"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-003"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "other", "", static_cast<int64_t>(1), static_cast<int64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-003"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    modelnet::Grp17 zero;
    BOOST_CHECK(zero.Apply("DS-AUTH-003", "", "clock", "", static_cast<int64_t>(-1), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(zero.stored("DS-AUTH-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(zero.text_of("DS-AUTH-003"), "clock");
    BOOST_CHECK(!zero.Apply("DS-AUTH-003", "", "later", "", static_cast<int64_t>(-2), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(zero.stored("DS-AUTH-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(zero.text_of("DS-AUTH-003"), "clock");
    BOOST_CHECK_EQUAL(eng.classification("DS-AUTH-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_AUTH_004)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-AUTH-004", "", "scope-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-004"), "scope-a");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-004"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-004", "", "scope-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-004"), "scope-a");
    BOOST_CHECK(!eng.Apply("DS-AUTH-004", "", "scope-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-004"), "scope-a");
    BOOST_CHECK_EQUAL(eng.classification("DS-AUTH-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_AUTH_005)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-AUTH-005", "", "contain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-005"));
    BOOST_CHECK(eng.Apply("DS-AUTH-005", "", "read", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-005"), "read");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-005"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-005", "", "effect", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-005"), "read");
    BOOST_CHECK(!eng.Apply("DS-AUTH-005", "", "contain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-005"), "read");
    modelnet::Grp17 effect;
    BOOST_CHECK(effect.Apply("DS-AUTH-005", "", "effect", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(effect.stored("DS-AUTH-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(effect.text_of("DS-AUTH-005"), "effect");
    modelnet::Grp17 release;
    BOOST_CHECK(release.Apply("DS-AUTH-005", "", "release", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(release.stored("DS-AUTH-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(release.text_of("DS-AUTH-005"), "release");
    modelnet::Grp17 spend;
    BOOST_CHECK(spend.Apply("DS-AUTH-005", "", "spend", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(spend.stored("DS-AUTH-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(spend.text_of("DS-AUTH-005"), "spend");
    BOOST_CHECK(!spend.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(spend.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(spend.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("DS-AUTH-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_AUTH_006)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-AUTH-006", "", "prep", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-006"));
    BOOST_CHECK(eng.Apply("DS-AUTH-006", "", "prep", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-006"), "prep");
    BOOST_CHECK(!eng.bit_of("DS-AUTH-006"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-006"), "prep");
    BOOST_CHECK(!eng.Apply("DS-AUTH-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-006"), "prep");
    BOOST_CHECK_EQUAL(eng.classification("DS-AUTH-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DATA_001)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DATA-001", "", "orig", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-DATA-001"));
    BOOST_CHECK(eng.Apply("DS-DATA-001", "", "orig", "prov", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-001"), "orig");
    BOOST_CHECK(!eng.bit_of("DS-DATA-001"));
    BOOST_CHECK(!eng.Apply("DS-DATA-001", "", "altered", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-001"), "orig");
    BOOST_CHECK(!eng.Apply("DS-DATA-001", "", "altered", "prov2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-001"), "orig");
    BOOST_CHECK_EQUAL(eng.classification("DS-DATA-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DATA_002)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DATA-002", "", "sensor", "sensor", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-DATA-002"));
    BOOST_CHECK(eng.Apply("DS-DATA-002", "", "sensor", "disputed", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-002"), "sensor|disputed");
    BOOST_CHECK(!eng.bit_of("DS-DATA-002"));
    BOOST_CHECK(!eng.Apply("DS-DATA-002", "", "sensor", "sensor", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-002"), "sensor|disputed");
    BOOST_CHECK(!eng.Apply("DS-DATA-002", "", "other", "fact", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-002"), "sensor|disputed");
    modelnet::Grp17 bare;
    BOOST_CHECK(bare.Apply("DS-DATA-002", "", "sensor", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(bare.stored("DS-DATA-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(bare.text_of("DS-DATA-002"), "sensor");
    BOOST_CHECK(!bare.Apply("DS-DATA-002", "", "sensor", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(bare.text_of("DS-DATA-002"), "sensor");
    BOOST_CHECK_EQUAL(eng.classification("DS-DATA-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DATA_003)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-DATA-003"));
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(1001), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-DATA-003", "", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(1000), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-003"), static_cast<int64_t>(1000));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-003"), "q");
    BOOST_CHECK(!eng.bit_of("DS-DATA-003"));
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-003"), static_cast<int64_t>(1000));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-003"), "q");
    modelnet::Grp17 low;
    BOOST_CHECK(low.Apply("DS-DATA-003", "", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(low.stored("DS-DATA-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(low.text_of("DS-DATA-003"), "q");
    BOOST_CHECK_EQUAL(eng.classification("DS-DATA-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DATA_004)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "", "local-body", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-DATA-004"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-DATA-004", "", "local-body", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-004"), "local-body");
    BOOST_CHECK(!eng.bit_of("DS-DATA-004"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "", "export", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-004"), "local-body");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "", "export", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-004"), "local-body");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("DS-DATA-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp17 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NO-SUCH", "", "text", "extra", static_cast<int64_t>(1), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.classification("NO-SUCH"), "COMPONENT");
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
