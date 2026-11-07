// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp15/grp15.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp15& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp15_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_ASR_PLN_005)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PLN-005", "busy", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "QUIET");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-005"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-005", "busy", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "QUIET");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-005"));
    BOOST_CHECK(eng.Apply("ASR-PLN-005", "quiesce", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-005"), "quiesce");
    BOOST_CHECK(eng.bit_of("ASR-PLN-005"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-005", "quiesce", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-005"), "quiesce");
    BOOST_CHECK(eng.bit_of("ASR-PLN-005"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-005", "busy", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "QUIET");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-005"), "quiesce");
    BOOST_CHECK(eng.bit_of("ASR-PLN-005"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PLN-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PLN_006)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.bit_of("ASR-PLN-006"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK(eng.Apply("ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-006"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-006"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK(!eng.Apply("ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PLN-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PLN_007)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "HISTORY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-007"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-007"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.Apply("ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "HISTORY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-007"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.Apply("ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-007"), static_cast<int64_t>(4));
    modelnet::Grp15 zero;
    BOOST_CHECK(zero.Apply("ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(zero.stored("ASR-PLN-007"), static_cast<int64_t>(1));
    BOOST_CHECK(!zero.Apply("ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-5), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(zero.stored("ASR-PLN-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PLN-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PRG_001)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DELTA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-001"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-001"), static_cast<int64_t>(7));
    BOOST_CHECK(!eng.Apply("ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DELTA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-001"), static_cast<int64_t>(7));
    BOOST_CHECK(!eng.Apply("ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-001"), static_cast<int64_t>(7));
    modelnet::Grp15 neg;
    BOOST_CHECK(neg.Apply("ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(neg.stored("ASR-PRG-001"), static_cast<int64_t>(-2));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PRG-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PRG_002)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-002"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.bit_of("ASR-PRG-002"));
    BOOST_CHECK(eng.Apply("ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-002"), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.bit_of("ASR-PRG-002"));
    BOOST_CHECK(eng.Apply("ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-002"), static_cast<int64_t>(3));
    BOOST_CHECK(eng.bit_of("ASR-PRG-002"));
    BOOST_CHECK(!eng.Apply("ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-002"), static_cast<int64_t>(3));
    BOOST_CHECK(eng.bit_of("ASR-PRG-002"));
    BOOST_CHECK(!eng.Apply("ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK(eng.bit_of("ASR-PRG-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PRG-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PRG_003)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-PRG-003", "", "adam", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRG-003"), "adam");
    BOOST_CHECK(!eng.bit_of("ASR-PRG-003"));
    BOOST_CHECK(!eng.Apply("ASR-PRG-003", "", "adam", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRG-003"), "adam");
    BOOST_CHECK(!eng.Apply("ASR-PRG-003", "", "sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RECIPE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRG-003"), "adam");
    BOOST_CHECK_EQUAL(eng.classification("ASR-PRG-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PRG_004)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PRG-004", "kill", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.bit_of("ASR-PRG-004"));
    BOOST_CHECK(eng.Apply("ASR-PRG-004", "kill", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-004"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.bit_of("ASR-PRG-004"));
    BOOST_CHECK(!eng.Apply("ASR-PRG-004", "kill", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-004"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.bit_of("ASR-PRG-004"));
    BOOST_CHECK(!eng.Apply("ASR-PRG-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRG-004"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.bit_of("ASR-PRG-004"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PRG-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PRT_001)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PRT-001", "", "json", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENVELOPE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PRT-001"));
    BOOST_CHECK(eng.Apply("ASR-PRT-001", "", "btx", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-001"), "btx");
    BOOST_CHECK(!eng.Apply("ASR-PRT-001", "", "btx", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-001"), "btx");
    BOOST_CHECK(!eng.Apply("ASR-PRT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENVELOPE");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-001"), "btx");
    BOOST_CHECK_EQUAL(eng.classification("ASR-PRT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PRT_002)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "QUIET");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PRT-002"));
    BOOST_CHECK(!eng.Apply("ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "QUIET");
    BOOST_CHECK(!eng.bit_of("ASR-PRT-002"));
    BOOST_CHECK(eng.Apply("ASR-PRT-002", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.bit_of("ASR-PRT-002"));
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-002"), "");
    BOOST_CHECK(eng.Apply("ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-002"), "quiesced");
    BOOST_CHECK(eng.bit_of("ASR-PRT-002"));
    BOOST_CHECK_EQUAL(eng.stored("ASR-PRT-002"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRT-002"), "quiesced");
    BOOST_CHECK(eng.bit_of("ASR-PRT-002"));
    BOOST_CHECK(!eng.Apply("ASR-PRT-002", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.bit_of("ASR-PRT-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PRT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PUB_001)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PUB-001", "publish", "pack", "body", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "OUTSIDE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PUB-001"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-PUB-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OUTSIDE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.bit_of("ASR-PUB-001"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PUB-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PUB_002)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PUB-002", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HISTORY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-002"), "");
    BOOST_CHECK(eng.Apply("ASR-PUB-002", "", "note", "hist", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-002"), "note");
    BOOST_CHECK(!eng.Apply("ASR-PUB-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HISTORY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-002"), "note");
    BOOST_CHECK(!eng.Apply("ASR-PUB-002", "", "other", "hist", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-002"), "note");
    BOOST_CHECK_EQUAL(eng.classification("ASR-PUB-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PUB_003)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PUB-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOC");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("ASR-PUB-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-003"), "readme");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("ASR-PUB-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOC");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-003"), "readme");
    BOOST_CHECK(!eng.Apply("ASR-PUB-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-003"), "readme");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("ASR-PUB-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PUB_004)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PUB-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("ASR-PUB-004", "", "mit", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PUB-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-004"), "mit");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-PUB-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-004"), "mit");
    BOOST_CHECK(!eng.Apply("ASR-PUB-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-004"), "mit");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("ASR-PUB-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_REC_001)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-REC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-001"), static_cast<int64_t>(11));
    BOOST_CHECK(!eng.bit_of("ASR-REC-001"));
    BOOST_CHECK(eng.Apply("ASR-REC-001", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.bit_of("ASR-REC-001"));
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-001"), static_cast<int64_t>(11));
    BOOST_CHECK(!eng.Apply("ASR-REC-001", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-001"), static_cast<int64_t>(11));
    BOOST_CHECK(eng.bit_of("ASR-REC-001"));
    BOOST_CHECK(!eng.Apply("ASR-REC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-001"), static_cast<int64_t>(11));
    modelnet::Grp15 first_fail;
    BOOST_CHECK(first_fail.Apply("ASR-REC-001", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(first_fail.bit_of("ASR-REC-001"));
    BOOST_CHECK_EQUAL(first_fail.stored("ASR-REC-001"), static_cast<int64_t>(0));
    BOOST_CHECK(first_fail.Apply("ASR-REC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(first_fail.stored("ASR-REC-001"), static_cast<int64_t>(8));
    BOOST_CHECK(first_fail.bit_of("ASR-REC-001"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-REC-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_REC_002)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "PREFIX");
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PREFIX");
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-002"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.Apply("ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "PREFIX");
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-002"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.Apply("ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-REC-002"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.classification("ASR-REC-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp15 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NO-SUCH", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("NO-SUCH"));
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.classification("NO-SUCH"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
