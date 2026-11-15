// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp22/grp22.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp22& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp22_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_DS_POOL_005)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("DS-NO-SUCH", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DS-NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("DS-NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.classification("DS-NO-SUCH"), "COMPONENT");
    BOOST_CHECK_EQUAL(eng.classification(""), "COMPONENT");

    BOOST_CHECK(!eng.Apply("DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-005"));
    BOOST_CHECK(!eng.Apply("DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-005"));
    BOOST_CHECK(eng.Apply("DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-005"), "cap");
    BOOST_CHECK(!eng.bit_of("DS-POOL-005"));
    BOOST_CHECK(!eng.Apply("DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-005"), "cap");
    BOOST_CHECK(!eng.Apply("DS-POOL-005", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-005"), "cap");
    BOOST_CHECK(!eng.Apply("DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-005"), "cap");
    BOOST_CHECK_EQUAL(eng.classification("DS-POOL-005"), "COMPONENT");
    Idle(eng);

    modelnet::Grp22 wide;
    BOOST_CHECK(wide.Apply("DS-POOL-005", "", "wide", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(wide.stored("DS-POOL-005"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(wide.text_of("DS-POOL-005"), "cap");
    BOOST_CHECK(!wide.bit_of("DS-POOL-005"));
    BOOST_CHECK(!wide.Apply("DS-POOL-005", "", "wide", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(wide.stored("DS-POOL-005"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(wide.text_of("DS-POOL-005"), "cap");
    BOOST_CHECK(!wide.Apply("DS-POOL-005", "", "z", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(wide.stored("DS-POOL-005"), static_cast<int64_t>(100));
    BOOST_CHECK(!wide.Apply("DS-POOL-005", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(wide.stored("DS-POOL-005"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(wide.text_of("DS-POOL-005"), "cap");
    BOOST_CHECK(!wide.qualified());
    Idle(wide);
}

BOOST_AUTO_TEST_CASE(req_DS_POOL_006)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-POOL-006", "", "self", "self", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-POOL-006"));
    BOOST_CHECK(eng.Apply("DS-POOL-006", "", "self", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-006"), "self");
    BOOST_CHECK(!eng.bit_of("DS-POOL-006"));
    BOOST_CHECK(!eng.Apply("DS-POOL-006", "", "self", "third", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-006"), "self");
    BOOST_CHECK(!eng.Apply("DS-POOL-006", "", "self", "self", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-006"), "self");
    BOOST_CHECK(eng.Apply("DS-POOL-006", "", "next", "z", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-POOL-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-POOL-006"), "next");
    BOOST_CHECK_EQUAL(eng.classification("DS-POOL-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_REC_001)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-REC-001", "", "origin-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SOURCE");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-REC-001"));
    BOOST_CHECK(eng.Apply("DS-REC-001", "", "origin-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-001"), "origin-1");
    BOOST_CHECK(!eng.bit_of("DS-REC-001"));
    BOOST_CHECK(!eng.Apply("DS-REC-001", "", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SOURCE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-001"), "origin-1");
    BOOST_CHECK(!eng.Apply("DS-REC-001", "", "origin-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-001"), "origin-1");
    BOOST_CHECK_EQUAL(eng.classification("DS-REC-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_REC_002)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-REC-002", "", "leader-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-002"), "leader-a");
    BOOST_CHECK(!eng.bit_of("DS-REC-002"));
    BOOST_CHECK(!eng.Apply("DS-REC-002", "", "leader-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-002"), "leader-a");
    BOOST_CHECK(!eng.Apply("DS-REC-002", "other", "leader-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FENCE");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-002"), "leader-a");
    BOOST_CHECK(!eng.bit_of("DS-REC-002"));
    BOOST_CHECK_EQUAL(eng.classification("DS-REC-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_REC_003)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-REC-003", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-REC-003"));
    BOOST_CHECK(eng.Apply("DS-REC-003", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-003"), "kept");
    BOOST_CHECK(!eng.bit_of("DS-REC-003"));
    BOOST_CHECK(!eng.Apply("DS-REC-003", "", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-003"), "kept");
    BOOST_CHECK(!eng.Apply("DS-REC-003", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-003"), "kept");
    BOOST_CHECK_EQUAL(eng.classification("DS-REC-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_REC_004)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-REC-004", "", "invoice", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-004"), "invoice");
    BOOST_CHECK(!eng.bit_of("DS-REC-004"));
    BOOST_CHECK(!eng.Apply("DS-REC-004", "payrecover", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-004"), "invoice");
    BOOST_CHECK(!eng.bit_of("DS-REC-004"));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Apply("DS-REC-004", "", "invoice", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-004"), "invoice");
    BOOST_CHECK_EQUAL(eng.classification("DS-REC-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_REC_005)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-REC-005", "", "hyp-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-005"), "hyp-1");
    BOOST_CHECK(!eng.bit_of("DS-REC-005"));
    BOOST_CHECK(eng.Apply("DS-REC-005", "correct", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-005"), "hyp-1");
    BOOST_CHECK(eng.bit_of("DS-REC-005"));
    BOOST_CHECK(!eng.Apply("DS-REC-005", "correct", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-005"), "hyp-1");
    BOOST_CHECK(eng.bit_of("DS-REC-005"));
    BOOST_CHECK_EQUAL(eng.classification("DS-REC-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_REC_006)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-REC-006", "", "partition clock response", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-REC-006"));
    const std::string full = "partition clock response liquidity";
    BOOST_CHECK(eng.Apply("DS-REC-006", "", full, "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-006"), full);
    BOOST_CHECK(eng.bit_of("DS-REC-006"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("DS-REC-006", "", full, "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.bit_of("DS-REC-006"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-006"), full);
    BOOST_CHECK(!eng.Apply("DS-REC-006", "", "partition clock response", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK(eng.bit_of("DS-REC-006"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-006"), full);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-REC-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_SHARE_001)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-SHARE-001", "", "no-mark", "alice", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TLP");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-001"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-001", "", "tlp-green", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TLP");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-001"), "");
    BOOST_CHECK(eng.Apply("DS-SHARE-001", "", "tlp-green", "alice", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-001"), "tlp-green|alice");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-001"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-001", "", "tlp-green", "bob", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-001"), "tlp-green|alice");
    BOOST_CHECK_EQUAL(eng.classification("DS-SHARE-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_SHARE_002)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "EMBARGO");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-002"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "EMBARGO");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-002"));
    BOOST_CHECK(eng.Apply("DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(11), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-002"), static_cast<int64_t>(11));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-002"), "held");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-002"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "", "held", "", static_cast<int64_t>(12), static_cast<int64_t>(11), false, err));
    BOOST_CHECK_EQUAL(err, "EMBARGO");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-002"), static_cast<int64_t>(11));
    BOOST_CHECK(!eng.bit_of("DS-SHARE-002"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(11), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-002"), static_cast<int64_t>(11));
    BOOST_CHECK(!eng.bit_of("DS-SHARE-002"));
    BOOST_CHECK_EQUAL(eng.classification("DS-SHARE-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_SHARE_003)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-SHARE-003", "", "public-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SANITIZE");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-003"));
    BOOST_CHECK(eng.Apply("DS-SHARE-003", "", "public-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-003"), "public-note");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-003"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-SHARE-003", "", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SANITIZE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-003"), "public-note");
    BOOST_CHECK(!eng.Apply("DS-SHARE-003", "", "public-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-003"), "public-note");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-SHARE-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_SHARE_004)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-SHARE-004", "", "aa", "bb", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LEAK");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-004"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LEAK");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-004"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-SHARE-004", "", "aa", "aa", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-004"), "aa");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-004"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-004", "", "aa", "bb", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LEAK");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-004"), "aa");
    BOOST_CHECK(!eng.Apply("DS-SHARE-004", "", "aa", "aa", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-004"), "aa");
    BOOST_CHECK_EQUAL(eng.classification("DS-SHARE-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_SHARE_005)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-SHARE-005", "force", "boom", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LOCAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-005"));
    BOOST_CHECK(eng.Apply("DS-SHARE-005", "retract", "note-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-005"), "note-1");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-005"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-005", "force", "boom", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "LOCAL");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-005"), "note-1");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-005"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-005", "retract", "note-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-005"), "note-1");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-005"));
    BOOST_CHECK_EQUAL(eng.classification("DS-SHARE-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_SHARE_006)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-SHARE-006", "use", "row-1", "share", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-006"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-006", "use", "row-1", "share-only", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-006"), "");
    BOOST_CHECK(!eng.Apply("DS-SHARE-006", "train", "row-1", "can-share-this", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-006"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-SHARE-006", "train", "row-1", "train", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-SHARE-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-006"), "row-1");
    BOOST_CHECK(!eng.bit_of("DS-SHARE-006"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-006", "train", "row-1", "share", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-006"), "row-1");
    BOOST_CHECK(!eng.Apply("DS-SHARE-006", "train", "row-1", "train", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-006"), "row-1");
    BOOST_CHECK_EQUAL(eng.classification("DS-SHARE-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_STD_001)
{
    modelnet::Grp22 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-STD-001", "", "", "ext", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "STIX");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-STD-001"));
    BOOST_CHECK(!eng.Apply("DS-STD-001", "", "indicator", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "STIX");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-001"), "");
    BOOST_CHECK(eng.Apply("DS-STD-001", "", "indicator", "ext", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-001"), "indicator");
    BOOST_CHECK(!eng.bit_of("DS-STD-001"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("DS-STD-001", "", "indicator", "other-ext", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-001"), "indicator");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-STD-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
