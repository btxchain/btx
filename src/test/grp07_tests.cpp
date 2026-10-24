// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp07/grp07.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp07& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp07_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_DT_OPT_001)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-OPT-001", "", "adam", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RECIPE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-001"));
    BOOST_CHECK(eng.Apply("DT-OPT-001", "", "adamw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-001"), "adamw");
    BOOST_CHECK(!eng.bit_of("DT-OPT-001"));
    BOOST_CHECK(!eng.Apply("DT-OPT-001", "", "sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-001"), "adamw");
    BOOST_CHECK(!eng.bit_of("DT-OPT-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_OPT_002)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-OPT-002", "adam", "draft", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-002"));
    BOOST_CHECK(!eng.Apply("DT-OPT-002", "", "matrix", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RULE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-002"));
    BOOST_CHECK(eng.Apply("DT-OPT-002", "adam", "matrix", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-002"), "matrix");
    BOOST_CHECK(!eng.bit_of("DT-OPT-002"));
    BOOST_CHECK(!eng.Apply("DT-OPT-002", "sgd", "matrix", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-002"), "matrix");
    BOOST_CHECK(!eng.bit_of("DT-OPT-002"));
    BOOST_CHECK(eng.Apply("DT-OPT-002", "sgd", "scalar", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-002"), "scalar");
    BOOST_CHECK(!eng.bit_of("DT-OPT-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_OPT_003)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-OPT-003", "", "finite", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-003"));
    BOOST_CHECK(eng.Apply("DT-OPT-003", "", "finite", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-003"), static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-003"), "w");
    BOOST_CHECK(!eng.bit_of("DT-OPT-003"));
    BOOST_CHECK(!eng.Apply("DT-OPT-003", "", "finite", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-003"), static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-003"), "w");
    BOOST_CHECK(!eng.bit_of("DT-OPT-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_OPT_004)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-OPT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-004"));
    BOOST_CHECK(!eng.Apply("DT-OPT-004", "", "m|s|r|k", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-004"));
    BOOST_CHECK(eng.Apply("DT-OPT-004", "", "m|s|r|k", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-004"), "m|s|r|k");
    BOOST_CHECK(!eng.bit_of("DT-OPT-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_OPT_005)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-OPT-005", "", "fp8", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-005"));
    BOOST_CHECK(eng.Apply("DT-OPT-005", "", "fp32", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-005"), "fp32");
    BOOST_CHECK(!eng.bit_of("DT-OPT-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_OPT_006)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-OPT-006", "", "fp4-weight", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-OPT-006"));
    BOOST_CHECK(eng.Apply("DT-OPT-006", "", "fp4-cache", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-006"), "fp4-cache");
    BOOST_CHECK(!eng.bit_of("DT-OPT-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_OPT_007)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-OPT-007", "", "adamw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-007"), "adamw");
    BOOST_CHECK(!eng.bit_of("DT-OPT-007"));
    BOOST_CHECK(!eng.Apply("DT-OPT-007", "", "sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-007"), "adamw");
    BOOST_CHECK(!eng.bit_of("DT-OPT-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_OPT_008)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-OPT-008", "draft", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-008"), "backbone");
    BOOST_CHECK(!eng.bit_of("DT-OPT-008"));
    BOOST_CHECK(!eng.Apply("DT-OPT-008", "backbone", "no", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RECIPE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-008"), "backbone");
    BOOST_CHECK(!eng.bit_of("DT-OPT-008"));
    BOOST_CHECK(eng.Apply("DT-OPT-008", "backbone", "authorized", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-008"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-008"), "backbone");
    BOOST_CHECK(!eng.bit_of("DT-OPT-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-OPT-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_DAT_001)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "training", "public_trajectory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-001"));
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "training", "private", "mit", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-001"));
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "other", "public_trajectory", "mit", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-001"));
    BOOST_CHECK(eng.Apply("DT-DAT-001", "training", "public_trajectory", "mit", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "public_trajectory");
    BOOST_CHECK(!eng.bit_of("DT-DAT-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_DAT_002)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-002", "other", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-002"));
    BOOST_CHECK(eng.Apply("DT-DAT-002", "training", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-002"), "training");
    BOOST_CHECK(!eng.bit_of("DT-DAT-002"));
    BOOST_CHECK(eng.Apply("DT-DAT-002", "validation", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-002"), "training");
    BOOST_CHECK(!eng.bit_of("DT-DAT-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_DAT_003)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PACK");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-003"));
    BOOST_CHECK(eng.Apply("DT-DAT-003", "", "b1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-003"), "b1");
    BOOST_CHECK(!eng.bit_of("DT-DAT-003"));
    BOOST_CHECK(!eng.Apply("DT-DAT-003", "", "b2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-003"), "b1");
    BOOST_CHECK(!eng.bit_of("DT-DAT-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_DAT_004)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-004", "", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-004"));
    BOOST_CHECK(eng.Apply("DT-DAT-004", "", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(7), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-004"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-004"), "c1");
    BOOST_CHECK(!eng.bit_of("DT-DAT-004"));
    BOOST_CHECK(!eng.Apply("DT-DAT-004", "", "c2", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-004"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-004"), "c1");
    BOOST_CHECK(!eng.bit_of("DT-DAT-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_DAT_005)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SHARD");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-005"));
    BOOST_CHECK(eng.Apply("DT-DAT-005", "", "shard-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-005"), "shard-a");
    BOOST_CHECK(!eng.bit_of("DT-DAT-005"));
    BOOST_CHECK(!eng.Apply("DT-DAT-005", "", "shard-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-005"), "shard-a");
    BOOST_CHECK(!eng.bit_of("DT-DAT-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_DAT_006)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-006", "", "learnable", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FREEZE");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-006"));
    BOOST_CHECK(eng.Apply("DT-DAT-006", "", "static", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-006"), "static");
    BOOST_CHECK(!eng.bit_of("DT-DAT-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_DAT_007)
{
    modelnet::Grp07 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-007", "", "solution-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LEAK");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-007"));
    BOOST_CHECK(eng.Apply("DT-DAT-007", "", "task", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-007"), "task");
    BOOST_CHECK(!eng.bit_of("DT-DAT-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

