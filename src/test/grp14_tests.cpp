// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp14/grp14.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp14& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp14_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_ASR_NAT_005)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NAT-005", "", "watcher", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-005"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-005", "", "watcher", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-005"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-005"));
    BOOST_CHECK(eng.Apply("ASR-NAT-005", "", "watcher", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-005"), "observer");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-005"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-005", "", "observer", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-005"), "observer");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-005"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-005", "", "observer", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-005"), "observer");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-005"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NAT-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NAT_006)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-NAT-006", "", "pinned", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-006"), "pinned");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-006"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-006", "", "pinned", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-006"), "pinned");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-006"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-006", "", "open", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-006"), "pinned");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-006"));
    BOOST_CHECK(!eng.Apply("ASR-NAT-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-006"), "pinned");
    BOOST_CHECK(!eng.bit_of("ASR-NAT-006"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NAT-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NET_001)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NET-001", "", "peer", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NET-001"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-NET-001", "", "peer", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NET-001"));
    BOOST_CHECK(!eng.Apply("ASR-NET-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NET-001"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.classification("ASR-NET-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NET_002)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NET-002", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NET-002"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-NET-002", "", "fast", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NET-002"));
    BOOST_CHECK(eng.Apply("ASR-NET-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-002"), "local");
    BOOST_CHECK(!eng.bit_of("ASR-NET-002"));
    BOOST_CHECK(!eng.Apply("ASR-NET-002", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-002"), "local");
    BOOST_CHECK(!eng.bit_of("ASR-NET-002"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-NET-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-002"), "local");
    BOOST_CHECK(!eng.bit_of("ASR-NET-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NET-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NET_003)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NET-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GRANT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NET-003"));
    BOOST_CHECK(eng.Apply("ASR-NET-003", "", "", "grant-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-003"), "grant-a");
    BOOST_CHECK(!eng.bit_of("ASR-NET-003"));
    BOOST_CHECK(!eng.Apply("ASR-NET-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GRANT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-003"), "grant-a");
    BOOST_CHECK(!eng.bit_of("ASR-NET-003"));
    BOOST_CHECK(!eng.Apply("ASR-NET-003", "", "", "grant-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-003"), "grant-a");
    BOOST_CHECK(!eng.bit_of("ASR-NET-003"));
    BOOST_CHECK(!eng.Apply("ASR-NET-003", "", "", "grant-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-003"), "grant-a");
    BOOST_CHECK(!eng.bit_of("ASR-NET-003"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NET-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NET_004)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-NET-004", "", "buf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NET-004"));
    BOOST_CHECK(eng.Apply("ASR-NET-004", "", "buf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-004"), "buf");
    BOOST_CHECK(eng.bit_of("ASR-NET-004"));
    BOOST_CHECK(!eng.Apply("ASR-NET-004", "", "next", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-004"), "buf");
    BOOST_CHECK(eng.bit_of("ASR-NET-004"));
    BOOST_CHECK(!eng.Apply("ASR-NET-004", "", "buf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-004"), "buf");
    BOOST_CHECK(eng.bit_of("ASR-NET-004"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NET-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_NET_005)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-NET-005", "", "unbounded", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-005"), "limited");
    BOOST_CHECK(eng.bit_of("ASR-NET-005"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("ASR-NET-005", "", "limited", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NET-005"), "limited");
    BOOST_CHECK(eng.bit_of("ASR-NET-005"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.classification("ASR-NET-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_OBS_001)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-OBS-001", "ready", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "STATUS");
    BOOST_CHECK_EQUAL(eng.stored("ASR-OBS-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-OBS-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-OBS-001"));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-OBS-001", "qualify", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-OBS-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-OBS-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-OBS-001"));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("ASR-OBS-001", "advertise", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-OBS-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-OBS-001"), "gpu");
    BOOST_CHECK(!eng.bit_of("ASR-OBS-001"));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-OBS-001", "qualify", "nic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-OBS-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-OBS-001"), "gpu");
    BOOST_CHECK(!eng.bit_of("ASR-OBS-001"));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("ASR-OBS-001", "advertise", "nic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-OBS-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-OBS-001"), "gpu");
    BOOST_CHECK(!eng.bit_of("ASR-OBS-001"));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("ASR-OBS-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PAY_001)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PAY-001", "", "same", "same", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-001"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-001", "", "a", "b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-001"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-001", "", "a", "b", static_cast<int64_t>(0), static_cast<int64_t>(-2), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-001"));
    BOOST_CHECK(eng.Apply("ASR-PAY-001", "", "lane", "other", static_cast<int64_t>(0), static_cast<int64_t>(7), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-001"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-001"), "lane");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-001"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-001", "", "lane", "lane", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-001"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-001"), "lane");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-001"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-001", "", "z", "y", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-001"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-001"), "lane");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-001"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-001", "", "new", "diff", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-001"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-001"), "lane");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-001"));
    modelnet::Grp14 empty_text;
    BOOST_CHECK(empty_text.Apply("ASR-PAY-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(empty_text.stored("ASR-PAY-001"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(empty_text.text_of("ASR-PAY-001"), "");
    BOOST_CHECK(!empty_text.bit_of("ASR-PAY-001"));
    BOOST_CHECK(!empty_text.Apply("ASR-PAY-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(6), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(empty_text.stored("ASR-PAY-001"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(empty_text.text_of("ASR-PAY-001"), "");
    BOOST_CHECK(!empty_text.bit_of("ASR-PAY-001"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PAY-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PAY_002)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-PAY-002", "", "claim-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-002"), "claim-a");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-002"));
    BOOST_CHECK(eng.Apply("ASR-PAY-002", "fail", "lost", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-002"), "claim-a");
    BOOST_CHECK(eng.bit_of("ASR-PAY-002"));
    BOOST_CHECK(eng.Apply("ASR-PAY-002", "fail", "lost", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-002"), "claim-a");
    BOOST_CHECK(eng.bit_of("ASR-PAY-002"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-002", "again", "claim-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-002"), "claim-a");
    BOOST_CHECK(eng.bit_of("ASR-PAY-002"));
    modelnet::Grp14 failed_first;
    BOOST_CHECK(failed_first.Apply("ASR-PAY-002", "fail", "claim-c", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(failed_first.stored("ASR-PAY-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(failed_first.text_of("ASR-PAY-002"), "claim-c");
    BOOST_CHECK(failed_first.bit_of("ASR-PAY-002"));
    BOOST_CHECK(!failed_first.Apply("ASR-PAY-002", "", "claim-d", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(failed_first.stored("ASR-PAY-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(failed_first.text_of("ASR-PAY-002"), "claim-c");
    BOOST_CHECK(failed_first.bit_of("ASR-PAY-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PAY-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PAY_003)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-PAY-003", "", "", "inv", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-003"), "inv");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-003"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-003", "", "", "inv", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-003"), "inv");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-003"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-003", "", "", "mutated", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TERMS");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-003"), "inv");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-003"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TERMS");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-003"), "inv");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-003"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PAY-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PAY_004)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PAY-004", "payout", "mode", "routed", static_cast<int64_t>(1), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-004"));
    BOOST_CHECK(!eng.Apply("ASR-PAY-004", "refund", "mode", "routed", static_cast<int64_t>(1), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PAY-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PAY-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PAY-004"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PAY-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PLN_001)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PLN-001", "replace", "session", "m9", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PLAN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-001"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-001", "", "", "m1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PLAN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-001"));
    BOOST_CHECK(eng.Apply("ASR-PLN-001", "", "frontier", "m1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "frontier");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-001"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-001", "replace", "", "m2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PLAN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "frontier");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-001"));
    BOOST_CHECK(eng.Apply("ASR-PLN-001", "replace", "session", "m2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "frontier");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-001"));
    BOOST_CHECK(eng.Apply("ASR-PLN-001", "replace", "other-model", "m3", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "frontier");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-001"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-001", "", "other", "m4", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "frontier");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-001"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PLN-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PLN_002)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PLN-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CURSOR");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-002"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-002"));
    BOOST_CHECK(eng.Apply("ASR-PLN-002", "", "wake-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-002"), "wake-a");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-002"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-002", "", "wake-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-002"), "wake-a");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-002"));
    BOOST_CHECK(eng.Apply("ASR-PLN-002", "", "wake-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-002"), "wake-b");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-002"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CURSOR");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-002"), "wake-b");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-002"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-002", "", "wake-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-002"), "wake-b");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-002"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PLN-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PLN_003)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PLN-003", "", "z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GEN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-003", "", "z", "", static_cast<int64_t>(0), static_cast<int64_t>(-5), false, err));
    BOOST_CHECK_EQUAL(err, "GEN");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK(eng.Apply("ASR-PLN-003", "", "g4", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "g4");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-003", "", "old", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "g4");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK(eng.Apply("ASR-PLN-003", "", "g4b", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "g4b");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-003", "", "no", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "g4b");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK(eng.Apply("ASR-PLN-003", "", "g7", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "g7");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-003", "", "g6", "", static_cast<int64_t>(0), static_cast<int64_t>(6), false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-003"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-003"), "g7");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-003"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PLN-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_ASR_PLN_004)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("ASR-PLN-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-004"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-004"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-004"), "");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-004"));
    BOOST_CHECK(eng.Apply("ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-004"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-004"), "8");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-004"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-004"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-004"), "8");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-004"));
    BOOST_CHECK(!eng.Apply("ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "COST");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-004"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-004"), "8");
    BOOST_CHECK(!eng.bit_of("ASR-PLN-004"));
    modelnet::Grp14 low;
    BOOST_CHECK(low.Apply("ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(low.stored("ASR-PLN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(low.text_of("ASR-PLN-004"), "1");
    BOOST_CHECK(!low.bit_of("ASR-PLN-004"));
    BOOST_CHECK(!low.Apply("ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(low.stored("ASR-PLN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(low.text_of("ASR-PLN-004"), "1");
    BOOST_CHECK(!low.bit_of("ASR-PLN-004"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-PLN-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(unknown_id)
{
    modelnet::Grp14 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK(!eng.bit_of(""));
    BOOST_CHECK(!eng.Apply("ASR-NO-SUCH", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("ASR-NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.classification("ASR-NO-SUCH"), "COMPONENT");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
