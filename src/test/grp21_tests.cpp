// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp21/grp21.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp21& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp21_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_DS_PAY_002)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PAY-002", "fund", "native", "own", static_cast<int64_t>(5), static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-PAY-002"));
    BOOST_CHECK(!eng.Apply("DS-PAY-002", "refund", "payout", "", static_cast<int64_t>(6), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-PAY-002"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PAY-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PAY_003)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PAY-003", "", "expiry fee stale", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-PAY-003"));
    BOOST_CHECK(eng.Apply("DS-PAY-003", "", "expiry fee stale watch", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-003"), "expiry fee stale watch");
    BOOST_CHECK(!eng.bit_of("DS-PAY-003"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("DS-PAY-003", "", "watch stale fee expiry", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-003"), "expiry fee stale watch");
    BOOST_CHECK(!eng.bit_of("DS-PAY-003"));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-003"), "expiry fee stale watch");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-PAY-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PAY_004)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PAY-004", "credit", "backing", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-PAY-004"));
    BOOST_CHECK(eng.Apply("DS-PAY-004", "", "backing", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-004"), "backing");
    BOOST_CHECK(!eng.bit_of("DS-PAY-004"));
    BOOST_CHECK(!eng.Apply("DS-PAY-004", "credit", "backing", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, err));
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-004"), "backing");
    BOOST_CHECK(!eng.bit_of("DS-PAY-004"));
    BOOST_CHECK(!eng.Apply("DS-PAY-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-004"), "backing");
    BOOST_CHECK(!eng.bit_of("DS-PAY-004"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PAY-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PAY_005)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PAY-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-PAY-005"));
    BOOST_CHECK(!eng.Apply("DS-PAY-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-PAY-005"));
    BOOST_CHECK(eng.Apply("DS-PAY-005", "", "prefund", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-005"), "prefund");
    BOOST_CHECK(!eng.bit_of("DS-PAY-005"));
    BOOST_CHECK(!eng.Apply("DS-PAY-005", "", "prefund", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-005"), "prefund");
    BOOST_CHECK(!eng.bit_of("DS-PAY-005"));
    BOOST_CHECK(!eng.Apply("DS-PAY-005", "", "prefund", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-005"), "prefund");
    BOOST_CHECK(!eng.bit_of("DS-PAY-005"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PAY-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PAY_006)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-PAY-006", "", "earned", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-006"), "earned");
    BOOST_CHECK(!eng.bit_of("DS-PAY-006"));
    BOOST_CHECK(eng.Apply("DS-PAY-006", "fail", "erased", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-006"), "earned");
    BOOST_CHECK(eng.bit_of("DS-PAY-006"));
    BOOST_CHECK(eng.Apply("DS-PAY-006", "reorg", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-006"), "earned");
    BOOST_CHECK(eng.bit_of("DS-PAY-006"));
    BOOST_CHECK(!eng.Apply("DS-PAY-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-006"), "earned");
    BOOST_CHECK(eng.bit_of("DS-PAY-006"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PAY-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PLAN_001)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PLAN-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HYPOTHESIS");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-001"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-001", "negative", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HYPOTHESIS");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-001"));
    BOOST_CHECK(eng.Apply("DS-PLAN-001", "", "h1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-001"), "h1");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-001"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-001", "", "h2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-001"), "h1");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-001"));
    BOOST_CHECK(eng.Apply("DS-PLAN-001", "negative", "erase-me", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-001"), "h1");
    BOOST_CHECK(eng.bit_of("DS-PLAN-001"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PLAN-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PLAN_002)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PLAN-002", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SERIAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-002"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-002", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SERIAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-002"));
    BOOST_CHECK(eng.Apply("DS-PLAN-002", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-002"), "left,right");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-002"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-002", "", "left", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-002"), "left,right");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-002"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-002", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SERIAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-002"), "left,right");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-002"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PLAN-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PLAN_003)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PROGRESS");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-003"));
    BOOST_CHECK(eng.Apply("DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(-2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-003"), static_cast<int64_t>(-2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-003"), "signal");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-003"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-003"), static_cast<int64_t>(-2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-003"), "signal");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-003"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PROGRESS");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-003"), static_cast<int64_t>(-2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-003"), "signal");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-003"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PLAN-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PLAN_004)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-PLAN-004", "", "evidence", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-004"), "evidence");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-004"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "", "replacement", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-004"), "evidence");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-004"));
    BOOST_CHECK(eng.Apply("DS-PLAN-004", "retract", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-004"), "evidence");
    BOOST_CHECK(eng.bit_of("DS-PLAN-004"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "", "replacement", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-004"), "evidence");
    BOOST_CHECK(eng.bit_of("DS-PLAN-004"));
    modelnet::Grp21 floor;
    BOOST_CHECK(floor.Apply("DS-PLAN-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(floor.stored("DS-PLAN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(floor.text_of("DS-PLAN-004"), "note");
    BOOST_CHECK(!floor.bit_of("DS-PLAN-004"));
    BOOST_CHECK(floor.Apply("DS-PLAN-004", "retract", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(floor.stored("DS-PLAN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(floor.text_of("DS-PLAN-004"), "note");
    BOOST_CHECK(floor.bit_of("DS-PLAN-004"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PLAN-004"), "COMPONENT");
    Idle(eng);
    Idle(floor);
}

BOOST_AUTO_TEST_CASE(req_DS_PLAN_005)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-005"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-005"));
    BOOST_CHECK(eng.Apply("DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-005"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-005"), "bound");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-005"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-005"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-005"), "bound");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-005"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-005"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-005"), "bound");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-005"));
    modelnet::Grp21 low;
    BOOST_CHECK(low.Apply("DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(low.stored("DS-PLAN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(low.text_of("DS-PLAN-005"), "bound");
    BOOST_CHECK(!low.bit_of("DS-PLAN-005"));
    BOOST_CHECK(!low.Apply("DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(low.stored("DS-PLAN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(low.text_of("DS-PLAN-005"), "bound");
    BOOST_CHECK(!low.bit_of("DS-PLAN-005"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PLAN-005"), "COMPONENT");
    Idle(eng);
    Idle(low);
}

BOOST_AUTO_TEST_CASE(req_DS_PLAN_006)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PLAN-006", "lost", "procedure", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-006"));
    BOOST_CHECK(eng.Apply("DS-PLAN-006", "", "procedure", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-006"), "procedure");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-006"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-006"), "procedure");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-006"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-006", "lost", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("DS-PLAN-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-006"), "procedure");
    BOOST_CHECK(!eng.bit_of("DS-PLAN-006"));
    BOOST_CHECK_EQUAL(eng.classification("DS-PLAN-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_POOL_001)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-POOL-001", "", "budget", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-001"));
    BOOST_CHECK(eng.Apply("DS-POOL-001", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-001"), "readiness");
    BOOST_CHECK(!eng.bit_of("DS-POOL-001"));
    BOOST_CHECK(eng.Apply("DS-POOL-001", "", "incident", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-001"), "readiness,incident");
    BOOST_CHECK(!eng.bit_of("DS-POOL-001"));
    BOOST_CHECK(!eng.Apply("DS-POOL-001", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-001"), "readiness,incident");
    BOOST_CHECK(!eng.bit_of("DS-POOL-001"));
    BOOST_CHECK(eng.Apply("DS-POOL-001", "", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-001"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-001"), "readiness,incident,family");
    BOOST_CHECK(!eng.bit_of("DS-POOL-001"));
    BOOST_CHECK(!eng.Apply("DS-POOL-001", "", "incident", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-001"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-001"), "readiness,incident,family");
    BOOST_CHECK(!eng.bit_of("DS-POOL-001"));
    BOOST_CHECK(!eng.Apply("DS-POOL-001", "", "budget", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-001"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-001"), "readiness,incident,family");
    BOOST_CHECK(!eng.bit_of("DS-POOL-001"));
    BOOST_CHECK_EQUAL(eng.classification("DS-POOL-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_POOL_002)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-POOL-002", "", "", "lot-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-002"), "lot-a");
    BOOST_CHECK(!eng.bit_of("DS-POOL-002"));
    BOOST_CHECK(!eng.Apply("DS-POOL-002", "", "", "lot-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-002"), "lot-a");
    BOOST_CHECK(!eng.bit_of("DS-POOL-002"));
    BOOST_CHECK(!eng.Apply("DS-POOL-002", "", "", "lot-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-002"), "lot-a");
    BOOST_CHECK(!eng.bit_of("DS-POOL-002"));
    BOOST_CHECK_EQUAL(eng.classification("DS-POOL-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_POOL_003)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "BALANCE");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-003"));
    BOOST_CHECK(!eng.Apply("DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "BALANCE");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-003"));
    BOOST_CHECK(eng.Apply("DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(6), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-003"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-003"), "reconcile");
    BOOST_CHECK(!eng.bit_of("DS-POOL-003"));
    BOOST_CHECK(!eng.Apply("DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "BALANCE");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-003"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-003"), "reconcile");
    BOOST_CHECK(!eng.bit_of("DS-POOL-003"));
    BOOST_CHECK(!eng.Apply("DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-003"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-003"), "reconcile");
    BOOST_CHECK(!eng.bit_of("DS-POOL-003"));
    BOOST_CHECK_EQUAL(eng.classification("DS-POOL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_POOL_004)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-POOL-004", "", "membership", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-004"));
    BOOST_CHECK(!eng.Apply("DS-POOL-004", "", "dues", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-004"));
    BOOST_CHECK(!eng.Apply("DS-POOL-004", "", "work", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-004"));
    BOOST_CHECK(eng.Apply("DS-POOL-004", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-004"), "readiness");
    BOOST_CHECK(!eng.bit_of("DS-POOL-004"));
    BOOST_CHECK(!eng.Apply("DS-POOL-004", "", "work", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-004"), "readiness");
    BOOST_CHECK(!eng.bit_of("DS-POOL-004"));
    BOOST_CHECK(!eng.Apply("DS-POOL-004", "", "membership", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-004"), "readiness");
    BOOST_CHECK(!eng.bit_of("DS-POOL-004"));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-004"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.qualified());
    modelnet::Grp21 pay;
    BOOST_CHECK(!pay.Apply("DS-POOL-004", "", "work", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(pay.stored("DS-POOL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(pay.text_of("DS-POOL-004"), "");
    BOOST_CHECK(!pay.bit_of("DS-POOL-004"));
    BOOST_CHECK(pay.Apply("DS-POOL-004", "", "work", "", static_cast<int64_t>(0), static_cast<int64_t>(6), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pay.stored("DS-POOL-004"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(pay.text_of("DS-POOL-004"), "work");
    BOOST_CHECK(!pay.bit_of("DS-POOL-004"));
    BOOST_CHECK(!pay.Apply("DS-POOL-004", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pay.stored("DS-POOL-004"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(pay.text_of("DS-POOL-004"), "work");
    BOOST_CHECK(!pay.bit_of("DS-POOL-004"));
    BOOST_CHECK(!pay.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(pay.stored("DS-POOL-004"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(pay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("DS-POOL-004"), "COMPONENT");
    Idle(eng);
    Idle(pay);
}

BOOST_AUTO_TEST_CASE(unknown_id)
{
    modelnet::Grp21 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-NO-SUCH", "", "text", "extra", static_cast<int64_t>(1), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DS-NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("DS-NO-SUCH"));
    BOOST_CHECK(!eng.Apply("", "op", "text", "extra", static_cast<int64_t>(1), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK(!eng.bit_of(""));
    BOOST_CHECK_EQUAL(eng.classification("DS-NO-SUCH"), "COMPONENT");
    BOOST_CHECK_EQUAL(eng.classification(""), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
