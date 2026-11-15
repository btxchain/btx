// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp20/grp20.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp20& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp20_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_DS_MODEL_005)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-MODEL-005", "place", "room", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-005"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-005", "restrict", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LOCATION");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-005"));
    BOOST_CHECK(eng.Apply("DS-MODEL-005", "restrict", "region", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-005"), "");
    BOOST_CHECK(eng.bit_of("DS-MODEL-005"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-005", "place", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LOCATION");
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-005"), "");
    BOOST_CHECK(eng.Apply("DS-MODEL-005", "place", "room", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-005"), "room");
    BOOST_CHECK(eng.bit_of("DS-MODEL-005"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-005", "place", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-005"), "room");
    BOOST_CHECK_EQUAL(eng.classification("DS-MODEL-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_MODEL_006)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-MODEL-006", "use", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-006"), "cap");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-006"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-006", "use", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-006"), "cap");
    BOOST_CHECK(eng.Apply("DS-MODEL-006", "poison", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.bit_of("DS-MODEL-006"));
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-006"), "cap");
    BOOST_CHECK(!eng.Apply("DS-MODEL-006", "use", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-006"), "cap");
    BOOST_CHECK(eng.bit_of("DS-MODEL-006"));
    modelnet::Grp20 later;
    BOOST_CHECK(later.Apply("DS-MODEL-006", "poison", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(later.bit_of("DS-MODEL-006"));
    BOOST_CHECK_EQUAL(later.stored("DS-MODEL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(later.text_of("DS-MODEL-006"), "");
    BOOST_CHECK(!later.Apply("DS-MODEL-006", "use", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(later.stored("DS-MODEL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(later.text_of("DS-MODEL-006"), "");
    BOOST_CHECK_EQUAL(eng.classification("DS-MODEL-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_NAT_001)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-NAT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-NAT-001"));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.Apply("DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "SPAWN");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-001"), "");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(eng.Apply("DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-001"), "btxd");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.Apply("DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-001"), "btxd");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.classification("DS-NAT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_NAT_002)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-NAT-002", "drop", "parent", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRESERVE");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-NAT-002"));
    BOOST_CHECK(eng.Apply("DS-NAT-002", "keep", "parent", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-002"), "parent");
    BOOST_CHECK(!eng.Apply("DS-NAT-002", "drop", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRESERVE");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-002"), "parent");
    BOOST_CHECK(!eng.Apply("DS-NAT-002", "keep", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-002"), "parent");
    BOOST_CHECK_EQUAL(eng.classification("DS-NAT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_NAT_003)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-NAT-003", "", "fee", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SPEND");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-NAT-003"));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(eng.Apply("DS-NAT-003", "", "fee", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-003"), "fee");
    BOOST_CHECK(!eng.bit_of("DS-NAT-003"));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Apply("DS-NAT-003", "", "fee", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SPEND");
    BOOST_CHECK(!eng.bit_of("DS-NAT-003"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-003"), "fee");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Apply("DS-NAT-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-003"), "fee");
    BOOST_CHECK(!eng.bit_of("DS-NAT-003"));
    BOOST_CHECK_EQUAL(eng.classification("DS-NAT-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_NAT_004)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-NAT-004", "note", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-NAT-004"));
    BOOST_CHECK(eng.Apply("DS-NAT-004", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK(eng.bit_of("DS-NAT-004"));
    BOOST_CHECK(!eng.Apply("DS-NAT-004", "note", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK(eng.bit_of("DS-NAT-004"));
    modelnet::Grp20 first_fail;
    BOOST_CHECK(first_fail.Apply("DS-NAT-004", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(first_fail.stored("DS-NAT-004"), static_cast<int64_t>(9));
    BOOST_CHECK(first_fail.bit_of("DS-NAT-004"));
    BOOST_CHECK(first_fail.Apply("DS-NAT-004", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(first_fail.stored("DS-NAT-004"), static_cast<int64_t>(9));
    BOOST_CHECK(first_fail.bit_of("DS-NAT-004"));
    BOOST_CHECK_EQUAL(eng.classification("DS-NAT-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_NAT_005)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-NAT-005", "", "case", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-NAT-005"));
    BOOST_CHECK(eng.Apply("DS-NAT-005", "", "case", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-005"), "case");
    BOOST_CHECK(!eng.Apply("DS-NAT-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-005"), "case");
    BOOST_CHECK(!eng.Apply("DS-NAT-005", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-005"), "case");
    BOOST_CHECK_EQUAL(eng.classification("DS-NAT-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_NAT_006)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "", "opt", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OPTOUT");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-NAT-006"));
    BOOST_CHECK(eng.Apply("DS-NAT-006", "", "opt", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-006"), "opt");
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "", "opt", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OPTOUT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-006"), "opt");
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-006"), "opt");
    BOOST_CHECK_EQUAL(eng.classification("DS-NAT-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_OPS_001)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-OPS-001", "", "drill", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "READINESS");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-OPS-001"));
    BOOST_CHECK(eng.Apply("DS-OPS-001", "", "drill", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-001"), "drill");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-OPS-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-001"), "drill");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-OPS-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_OPS_002)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-OPS-002", "", "probe-live-target-sample", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BENIGN");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-OPS-002"));
    BOOST_CHECK(eng.Apply("DS-OPS-002", "", "control", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-002"), "control");
    BOOST_CHECK(!eng.Apply("DS-OPS-002", "", "x-live-target-y", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BENIGN");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-002"), "control");
    BOOST_CHECK(!eng.Apply("DS-OPS-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-002"), "control");
    BOOST_CHECK_EQUAL(eng.classification("DS-OPS-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_OPS_003)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "FIXTURE");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-OPS-003"));
    BOOST_CHECK(!eng.Apply("DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FIXTURE");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIXTURE");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-OPS-003", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-003"), "");
    BOOST_CHECK(!eng.Apply("DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "FIXTURE");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-003"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.classification("DS-OPS-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_OPS_004)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-OPS-004", "", "mitigation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EMBARGO");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-OPS-004"));
    BOOST_CHECK(eng.Apply("DS-OPS-004", "", "mitigation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-004"), "mitigation");
    BOOST_CHECK(!eng.Apply("DS-OPS-004", "", "mitigation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "EMBARGO");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-004"), "mitigation");
    BOOST_CHECK(!eng.Apply("DS-OPS-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-004"), "mitigation");
    BOOST_CHECK_EQUAL(eng.classification("DS-OPS-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_OPS_005)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-OPS-005", "", "private-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-OPS-005"));
    BOOST_CHECK(eng.Apply("DS-OPS-005", "", "public-patch", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-005"), "public-patch");
    BOOST_CHECK(!eng.Apply("DS-OPS-005", "", "still private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-005"), "public-patch");
    BOOST_CHECK(!eng.Apply("DS-OPS-005", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-005"), "public-patch");
    BOOST_CHECK_EQUAL(eng.classification("DS-OPS-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_OPS_006)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-OPS-006", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LOCAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-OPS-006"));
    BOOST_CHECK(eng.Apply("DS-OPS-006", "", "ignored", "partner", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-OPS-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-006"), "partner");
    BOOST_CHECK(!eng.Apply("DS-OPS-006", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LOCAL");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-006"), "partner");
    BOOST_CHECK(!eng.Apply("DS-OPS-006", "", "ignored", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-006"), "partner");
    BOOST_CHECK_EQUAL(eng.classification("DS-OPS-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_PAY_001)
{
    modelnet::Grp20 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MODE");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-PAY-001"));
    BOOST_CHECK(eng.Apply("DS-PAY-001", "", "exact", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-PAY-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-001"), "exact");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MODE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-001"), "exact");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-PAY-001"), "exact");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-PAY-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp20 eng;
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
