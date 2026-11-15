// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp10/grp10.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp10& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp10_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_DT_SIM_002)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SIM-002", "", "2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DEPENDENCY");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-002"));
    BOOST_CHECK(eng.Apply("DT-SIM-002", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-002"), "1");
    BOOST_CHECK(!eng.bit_of("DT-SIM-002"));
    BOOST_CHECK(eng.Apply("DT-SIM-002", "", "2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-002"), "2");
    BOOST_CHECK(!eng.bit_of("DT-SIM-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-002"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SIM_003)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SIM-003", "dualpipe", "", "", static_cast<int64_t>(3), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-003"));
    BOOST_CHECK(!eng.Apply("DT-SIM-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "BUBBLE");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-003"));
    BOOST_CHECK(eng.Apply("DT-SIM-003", "", "", "", static_cast<int64_t>(3), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-003"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-003"), "8/2");
    BOOST_CHECK(!eng.bit_of("DT-SIM-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-003"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SIM_004)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SIM-004", "", "fused-time", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SWEEP");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-004"));
    BOOST_CHECK(eng.Apply("DT-SIM-004", "", "bandwidth", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-004"), "bandwidth");
    BOOST_CHECK(!eng.bit_of("DT-SIM-004"));
    BOOST_CHECK(eng.Apply("DT-SIM-004", "", "latency", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-004"), "latency");
    BOOST_CHECK(!eng.bit_of("DT-SIM-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-004"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SIM_005)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SIM-005", "", "missing", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-005"));
    BOOST_CHECK(eng.Apply("DT-SIM-005", "", "model", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-005"), "model");
    BOOST_CHECK(!eng.bit_of("DT-SIM-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-005"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SIM_006)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SIM-006", "2", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-006"));
    BOOST_CHECK(eng.Apply("DT-SIM-006", "0", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-006"));
    BOOST_CHECK(eng.Apply("DT-SIM-006", "1", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-006"));
    BOOST_CHECK(!eng.Apply("DT-SIM-006", "check", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DISAGREE");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-006"));
    BOOST_CHECK(eng.Apply("DT-SIM-006", "1", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-006"));
    BOOST_CHECK(eng.Apply("DT-SIM-006", "check", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-006"), "agree");
    BOOST_CHECK(eng.bit_of("DT-SIM-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-006"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SIM_007)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-SIM-007", "", "loss", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-SIM-007"));
    BOOST_CHECK(eng.Apply("DT-SIM-007", "", "throughput", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-007"), "throughput");
    BOOST_CHECK(!eng.bit_of("DT-SIM-007"));
    BOOST_CHECK(eng.Apply("DT-SIM-007", "", "quality", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-007"), "quality");
    BOOST_CHECK(!eng.bit_of("DT-SIM-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-007"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_SIM_008)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-SIM-008", "commit", "g1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-008"), "g1");
    BOOST_CHECK(!eng.bit_of("DT-SIM-008"));
    BOOST_CHECK(eng.Apply("DT-SIM-008", "commit", "g2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-008"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-008"), "g2");
    BOOST_CHECK(!eng.bit_of("DT-SIM-008"));
    BOOST_CHECK(!eng.Apply("DT-SIM-008", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FAILED");
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-008"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-008"), "g2");
    BOOST_CHECK(eng.bit_of("DT-SIM-008"));
    BOOST_CHECK(eng.Apply("DT-SIM-008", "rollback", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-SIM-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SIM-008"), "g1");
    BOOST_CHECK(eng.bit_of("DT-SIM-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-SIM-008"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_001)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OBLIGATION");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-001"));
    BOOST_CHECK(eng.Apply("DT-REL-001", "", "binding", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-001"), "binding");
    BOOST_CHECK(!eng.bit_of("DT-REL-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_002)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-002", "train", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-002"));
    BOOST_CHECK(eng.Apply("DT-REL-002", "startup", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-002"), "startup");
    BOOST_CHECK(!eng.bit_of("DT-REL-002"));
    BOOST_CHECK(eng.Apply("DT-REL-002", "shutdown", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-002"), "shutdown");
    BOOST_CHECK(!eng.bit_of("DT-REL-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_003)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-003", "", "image", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-003"));
    BOOST_CHECK(!eng.Apply("DT-REL-003", "ship", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_004)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-004", "", "fp8", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-004"), "fp8=absent");
    BOOST_CHECK(!eng.bit_of("DT-REL-004"));
    BOOST_CHECK(!eng.Apply("DT-REL-004", "", "rdma", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-004"), "rdma=absent");
    BOOST_CHECK(!eng.bit_of("DT-REL-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_005)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-005", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REFUSED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-005"));
    BOOST_CHECK(eng.Apply("DT-REL-005", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-005"), "readme");
    BOOST_CHECK(!eng.bit_of("DT-REL-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_006)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-006"));
    BOOST_CHECK(eng.Apply("DT-REL-006", "", "tree", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-006"), "tree");
    BOOST_CHECK(!eng.bit_of("DT-REL-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_007)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-007", "gpu", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-007"));
    BOOST_CHECK(!eng.Apply("DT-REL-007", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_REL_008)
{
    modelnet::Grp10 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-REL-008", "push", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-008"));
    BOOST_CHECK(!eng.Apply("DT-REL-008", "publish", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(eng.stored("DT-REL-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-REL-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-REL-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-REL-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

