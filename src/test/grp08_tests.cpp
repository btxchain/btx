// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp08/grp08.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp08& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp08_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_DT_DAT_008)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-DAT-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REVISION");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-DAT-008"));
    BOOST_CHECK(eng.Apply("DT-DAT-008", "", "r1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-008"), "r1");
    BOOST_CHECK(!eng.bit_of("DT-DAT-008"));
    BOOST_CHECK(!eng.Apply("DT-DAT-008", "", "r1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-008"), "r1");
    BOOST_CHECK(!eng.bit_of("DT-DAT-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-DAT-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_001)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-RLP-001", "", "p|s|t", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-RLP-001"));
    BOOST_CHECK(eng.Apply("DT-RLP-001", "", "p|s|t|g", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-001"), "p|s|t|g");
    BOOST_CHECK(!eng.bit_of("DT-RLP-001"));
    BOOST_CHECK(!eng.Apply("DT-RLP-001", "", "p|s|t|h", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "COMPAT");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-001"), "p|s|t|g");
    BOOST_CHECK(!eng.bit_of("DT-RLP-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-RLP-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_002)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-RLP-002", "", "2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GROUP");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-RLP-002"));
    BOOST_CHECK(eng.Apply("DT-RLP-002", "", "2,4", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-002"), "-1,1");
    BOOST_CHECK(!eng.bit_of("DT-RLP-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-RLP-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_003)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-RLP-003", "", "2,4", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GROUP");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-RLP-003"));
    BOOST_CHECK(eng.Apply("DT-RLP-003", "", "2,4", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-003"), "-1,1");
    BOOST_CHECK(!eng.bit_of("DT-RLP-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-RLP-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_004)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-RLP-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-RLP-004"));
    BOOST_CHECK(eng.Apply("DT-RLP-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-004"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-004"), "lag2");
    BOOST_CHECK(!eng.bit_of("DT-RLP-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-RLP-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_005)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-RLP-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-005"), "open");
    BOOST_CHECK(!eng.bit_of("DT-RLP-005"));
    BOOST_CHECK(eng.Apply("DT-RLP-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-005"), "full");
    BOOST_CHECK(!eng.bit_of("DT-RLP-005"));
    BOOST_CHECK(eng.Apply("DT-RLP-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-005"), "full");
    BOOST_CHECK(!eng.bit_of("DT-RLP-005"));
    BOOST_CHECK(!eng.Apply("DT-RLP-005", "need", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-005"), "full");
    BOOST_CHECK(!eng.bit_of("DT-RLP-005"));
    BOOST_CHECK(eng.Apply("DT-RLP-005", "need", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-005"), "full");
    BOOST_CHECK(!eng.bit_of("DT-RLP-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-RLP-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_008)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-RLP-008", "t", "t", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-RLP-008"));
    BOOST_CHECK(!eng.Apply("DT-RLP-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RIGHTS");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-RLP-008"));
    BOOST_CHECK(eng.Apply("DT-RLP-008", "teacher", "student", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-008"), "student");
    BOOST_CHECK(!eng.bit_of("DT-RLP-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-RLP-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_001)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-CKP-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-001"));
    BOOST_CHECK(eng.Apply("DT-CKP-001", "", "m1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-001"), "m1");
    BOOST_CHECK(!eng.bit_of("DT-CKP-001"));
    BOOST_CHECK(!eng.Apply("DT-CKP-001", "", "m2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-001"), "m1");
    BOOST_CHECK(!eng.bit_of("DT-CKP-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_002)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-CKP-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(128), true, err));
    BOOST_CHECK_EQUAL(err, "BUFFER");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-002"));
    BOOST_CHECK(!eng.Apply("DT-CKP-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4194305), false, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-002"));
    BOOST_CHECK(eng.Apply("DT-CKP-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4096), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-002"), static_cast<int64_t>(4096));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-002"), "piece");
    BOOST_CHECK(!eng.bit_of("DT-CKP-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_003)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-CKP-003", "", "PYTHON_PICKLE", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-003"));
    BOOST_CHECK(!eng.Apply("DT-CKP-003", "", "elf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-003"));
    BOOST_CHECK(eng.Apply("DT-CKP-003", "", "weights", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-003"), "weights");
    BOOST_CHECK(!eng.bit_of("DT-CKP-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_005)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-CKP-005", "", "g1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-005"));
    BOOST_CHECK(eng.Apply("DT-CKP-005", "", "g1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-005"), "g1");
    BOOST_CHECK(!eng.bit_of("DT-CKP-005"));
    BOOST_CHECK(!eng.Apply("DT-CKP-005", "", "g2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-005"), "g1");
    BOOST_CHECK(!eng.bit_of("DT-CKP-005"));
    BOOST_CHECK(eng.Apply("DT-CKP-005", "", "g2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-005"), "g2");
    BOOST_CHECK(!eng.bit_of("DT-CKP-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_006)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-CKP-006", "snap", "s1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-006"), "s1");
    BOOST_CHECK(!eng.bit_of("DT-CKP-006"));
    BOOST_CHECK(!eng.Apply("DT-CKP-006", "mutate", "s2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "IMMUTABLE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-006"), "s1");
    BOOST_CHECK(!eng.bit_of("DT-CKP-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_007)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-CKP-007", "", "PYTHON_PICKLE", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-007"));
    BOOST_CHECK(eng.Apply("DT-CKP-007", "export", "weights", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-007"), "weights");
    BOOST_CHECK(!eng.bit_of("DT-CKP-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_CKP_008)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-CKP-008", "promote", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-CKP-008"));
    BOOST_CHECK(eng.Apply("DT-CKP-008", "valid", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-008"), "valid");
    BOOST_CHECK(!eng.bit_of("DT-CKP-008"));
    BOOST_CHECK(!eng.Apply("DT-CKP-008", "activate", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-008"), "valid");
    BOOST_CHECK(!eng.bit_of("DT-CKP-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-CKP-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_WAN_001)
{
    modelnet::Grp08 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-WAN-001", "perlayer", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-WAN-001"));
    BOOST_CHECK(eng.Apply("DT-WAN-001", "coarse", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-WAN-001"), "coarse");
    BOOST_CHECK(!eng.bit_of("DT-WAN-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-WAN-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

