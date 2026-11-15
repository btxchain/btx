// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp06/grp06.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp06& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp06_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_DT_GRD_001)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-GRD-001", "init", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-001"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-001"), "w");
    BOOST_CHECK(!eng.bit_of("DT-GRD-001"));
    BOOST_CHECK(!eng.Apply("DT-GRD-001", "step", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-001"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-001"), "w");
    BOOST_CHECK(!eng.bit_of("DT-GRD-001"));
    BOOST_CHECK(eng.Apply("DT-GRD-001", "step", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-001"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-001"), "w");
    BOOST_CHECK(!eng.bit_of("DT-GRD-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-GRD-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_GRD_002)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-GRD-002", "", "mb1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-GRD-002"));
    BOOST_CHECK(eng.Apply("DT-GRD-002", "w0", "mb1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-002"), "w0");
    BOOST_CHECK(!eng.bit_of("DT-GRD-002"));
    BOOST_CHECK(!eng.Apply("DT-GRD-002", "w1", "mb1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-002"), "w0");
    BOOST_CHECK(!eng.bit_of("DT-GRD-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-GRD-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_GRD_004)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-GRD-004", "forward", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-004"), "alive");
    BOOST_CHECK(eng.bit_of("DT-GRD-004"));
    BOOST_CHECK(eng.Apply("DT-GRD-004", "remat", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-004"), "alive");
    BOOST_CHECK(eng.bit_of("DT-GRD-004"));
    BOOST_CHECK(eng.Apply("DT-GRD-004", "backward", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-004"), "alive");
    BOOST_CHECK(eng.bit_of("DT-GRD-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-GRD-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_GRD_005)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-GRD-005", "remat", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-005"), "route");
    BOOST_CHECK(!eng.bit_of("DT-GRD-005"));
    BOOST_CHECK(eng.Apply("DT-GRD-005", "token", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-005"), "token");
    BOOST_CHECK(!eng.bit_of("DT-GRD-005"));
    BOOST_CHECK(eng.Apply("DT-GRD-005", "remat", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-005"), "token");
    BOOST_CHECK(!eng.bit_of("DT-GRD-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-GRD-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_GRD_006)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-GRD-006", "bias", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-006"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-006"), "bias");
    BOOST_CHECK(!eng.bit_of("DT-GRD-006"));
    BOOST_CHECK(eng.Apply("DT-GRD-006", "mix", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-006"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-006"), "bias");
    BOOST_CHECK(!eng.bit_of("DT-GRD-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-GRD-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_GRD_007)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-GRD-007", "grad", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-007"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-007"), "grad");
    BOOST_CHECK(!eng.bit_of("DT-GRD-007"));
    BOOST_CHECK(eng.Apply("DT-GRD-007", "detach", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-007"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-007"), "grad");
    BOOST_CHECK(eng.bit_of("DT-GRD-007"));
    BOOST_CHECK(!eng.Apply("DT-GRD-007", "grad", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "DETACHED");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-007"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-007"), "grad");
    BOOST_CHECK(eng.bit_of("DT-GRD-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-GRD-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_GRD_008)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-GRD-008", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-GRD-008"));
    BOOST_CHECK(!eng.Apply("DT-GRD-008", "", "ced", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SHAPE");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-GRD-008"));
    BOOST_CHECK(eng.Apply("DT-GRD-008", "", "ced", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-008"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-008"), "ced");
    BOOST_CHECK(!eng.bit_of("DT-GRD-008"));
    BOOST_CHECK(!eng.Apply("DT-GRD-008", "advertise", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-008"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-008"), "ced");
    BOOST_CHECK(!eng.bit_of("DT-GRD-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-GRD-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_001)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-PAR-001", "", "0,1,1,1,1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-001"));
    BOOST_CHECK(eng.Apply("DT-PAR-001", "", "2,1,1,1,1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-001"), "2,1,1,1,1");
    BOOST_CHECK(!eng.bit_of("DT-PAR-001"));
    BOOST_CHECK(!eng.Apply("DT-PAR-001", "", "2,2,1,1,1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-001"), "2,1,1,1,1");
    BOOST_CHECK(!eng.bit_of("DT-PAR-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_002)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-PAR-002", "plan", "g", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-002"), "g");
    BOOST_CHECK(!eng.bit_of("DT-PAR-002"));
    BOOST_CHECK(eng.Apply("DT-PAR-002", "freeze", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-002"), "g");
    BOOST_CHECK(eng.bit_of("DT-PAR-002"));
    BOOST_CHECK(!eng.Apply("DT-PAR-002", "plan", "h", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-002"), "g");
    BOOST_CHECK(eng.bit_of("DT-PAR-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_003)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-PAR-003", "dispatch", "r1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-003"), "r1");
    BOOST_CHECK(!eng.bit_of("DT-PAR-003"));
    BOOST_CHECK(!eng.Apply("DT-PAR-003", "drop", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OPEN");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-003"), "r1");
    BOOST_CHECK(!eng.bit_of("DT-PAR-003"));
    BOOST_CHECK(eng.Apply("DT-PAR-003", "backward", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-003"), "done");
    BOOST_CHECK(!eng.bit_of("DT-PAR-003"));
    BOOST_CHECK(!eng.Apply("DT-PAR-003", "backward", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-003"), "done");
    BOOST_CHECK(!eng.bit_of("DT-PAR-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_004)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-PAR-004", "fused", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KERNEL");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-004"));
    BOOST_CHECK(eng.Apply("DT-PAR-004", "forward", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-004"), "forward");
    BOOST_CHECK(!eng.bit_of("DT-PAR-004"));
    BOOST_CHECK(eng.Apply("DT-PAR-004", "dgrad", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-004"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-004"), "dgrad");
    BOOST_CHECK(!eng.bit_of("DT-PAR-004"));
    BOOST_CHECK(eng.Apply("DT-PAR-004", "wgrad", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-004"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-004"), "wgrad");
    BOOST_CHECK(!eng.bit_of("DT-PAR-004"));
    BOOST_CHECK(!eng.Apply("DT-PAR-004", "forward", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-004"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-004"), "wgrad");
    BOOST_CHECK(!eng.bit_of("DT-PAR-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_005)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-PAR-005", "", "scalar", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "UNIT");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-005"));
    BOOST_CHECK(eng.Apply("DT-PAR-005", "", "matrix", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-005"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-005"), "matrix");
    BOOST_CHECK(!eng.bit_of("DT-PAR-005"));
    BOOST_CHECK(eng.Apply("DT-PAR-005", "", "head", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-005"), "head");
    BOOST_CHECK(!eng.bit_of("DT-PAR-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_006)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-PAR-006", "dualpipe", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-006"));
    BOOST_CHECK(!eng.Apply("DT-PAR-006", "", "overlap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_007)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-PAR-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-007"));
    BOOST_CHECK(eng.Apply("DT-PAR-007", "", "w", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-007"), "w");
    BOOST_CHECK(!eng.bit_of("DT-PAR-007"));
    BOOST_CHECK(!eng.Apply("DT-PAR-007", "", "w", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-007"), "w");
    BOOST_CHECK(!eng.bit_of("DT-PAR-007"));
    BOOST_CHECK(!eng.Apply("DT-PAR-007", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-007"), "w");
    BOOST_CHECK(!eng.bit_of("DT-PAR-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_PAR_008)
{
    modelnet::Grp06 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-PAR-008", "", "2,4", "1,0", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MASK");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-008"));
    BOOST_CHECK(!eng.Apply("DT-PAR-008", "", "2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-PAR-008"));
    BOOST_CHECK(eng.Apply("DT-PAR-008", "", "2,4", "1,3", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-008"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-008"), "3/2");
    BOOST_CHECK(!eng.bit_of("DT-PAR-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-PAR-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

