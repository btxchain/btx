// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp23/grp23.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp23& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp23_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_DS_STD_002)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-STD-002"));
    BOOST_CHECK(!eng.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(50), false, err));
    BOOST_CHECK_EQUAL(err, "TAXII");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-002"), "");
    BOOST_CHECK(eng.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-002"), "sync");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(40), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-002"), "sync");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-STD-002"), "COMPONENT");

    modelnet::Grp23 wide;
    BOOST_CHECK(wide.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(wide.stored("DS-STD-002"), static_cast<int64_t>(100));
    BOOST_CHECK(!wide.Apply("DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, err));
    BOOST_CHECK_EQUAL(err, "TAXII");
    BOOST_CHECK_EQUAL(wide.stored("DS-STD-002"), static_cast<int64_t>(100));
    BOOST_CHECK(!wide.qualified());
    Idle(eng);
    Idle(wide);
}

BOOST_AUTO_TEST_CASE(req_DS_STD_003)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-STD-003", "", "raw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OCSF");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-STD-003"));
    BOOST_CHECK(eng.Apply("DS-STD-003", "", "raw", "ver", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-003"), "raw");
    BOOST_CHECK(!eng.Apply("DS-STD-003", "", "raw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OCSF");
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-003"), "raw");
    BOOST_CHECK(!eng.Apply("DS-STD-003", "", "other", "ver2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-003"), "raw");
    BOOST_CHECK(!eng.Apply("DS-STD-003", "", "raw", "ver3", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-003"), "raw");
    BOOST_CHECK_EQUAL(eng.classification("DS-STD-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_STD_004)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-STD-004", "", "rule", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BACKEND");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-STD-004"));
    BOOST_CHECK(eng.Apply("DS-STD-004", "", "rule", "sigma", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-004"), "rule");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-STD-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BACKEND");
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-004"), "rule");
    BOOST_CHECK(!eng.Apply("DS-STD-004", "", "other", "sigma", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-004"), "rule");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-STD-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_STD_005)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-STD-005", "", "malformed", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "MALFORMED");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-STD-005"));
    BOOST_CHECK(!eng.Apply("DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MALFORMED");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-005"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "MALFORMED");
    BOOST_CHECK(!eng.Apply("DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(1000001), false, err));
    BOOST_CHECK_EQUAL(err, "MALFORMED");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-005"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(1000000), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-005"), static_cast<int64_t>(1000000));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-005"), "event");
    BOOST_CHECK(!eng.Apply("DS-STD-005", "", "malformed", "", static_cast<int64_t>(0), static_cast<int64_t>(1000000), false, err));
    BOOST_CHECK_EQUAL(err, "MALFORMED");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-005"), static_cast<int64_t>(1000000));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-005"), "event");
    BOOST_CHECK(!eng.Apply("DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-005"), static_cast<int64_t>(1000000));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-005"), "event");
    BOOST_CHECK_EQUAL(eng.classification("DS-STD-005"), "COMPONENT");

    modelnet::Grp23 low;
    BOOST_CHECK(low.Apply("DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(low.stored("DS-STD-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(low.text_of("DS-STD-005"), "event");
    Idle(eng);
    Idle(low);
}

BOOST_AUTO_TEST_CASE(req_DS_STD_006)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-STD-006", "", "drop", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CACAO");
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-STD-006"));
    BOOST_CHECK(eng.Apply("DS-STD-006", "", "contain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-STD-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-006"), "contain");
    BOOST_CHECK(!eng.Apply("DS-STD-006", "", "allow", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-006"), "contain");
    BOOST_CHECK(!eng.Apply("DS-STD-006", "", "exec", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CACAO");
    BOOST_CHECK_EQUAL(eng.text_of("DS-STD-006"), "contain");
    BOOST_CHECK_EQUAL(eng.classification("DS-STD-006"), "COMPONENT");

    modelnet::Grp23 deny;
    BOOST_CHECK(deny.Apply("DS-STD-006", "", "deny", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(deny.stored("DS-STD-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(deny.text_of("DS-STD-006"), "deny");
    modelnet::Grp23 log;
    BOOST_CHECK(log.Apply("DS-STD-006", "", "log", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(log.stored("DS-STD-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(log.text_of("DS-STD-006"), "log");
    modelnet::Grp23 allow;
    BOOST_CHECK(allow.Apply("DS-STD-006", "", "allow", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(allow.text_of("DS-STD-006"), "allow");
    Idle(eng);
    Idle(deny);
    Idle(log);
    Idle(allow);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_A)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("P2P-SCN-A", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-A"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-A"), "local");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-A"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("P2P-SCN-A", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-A"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-A"), "local");
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-A"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_B)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-B", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-B"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-B"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-B"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("P2P-SCN-B", "scan", "peer", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-B"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-B"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_C)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-C", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-C"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-C"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-C"));
    BOOST_CHECK(eng.Apply("P2P-SCN-C", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-C"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-C"), "lan");
    BOOST_CHECK(eng.bit_of("P2P-SCN-C"));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK(!eng.Apply("P2P-SCN-C", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-C"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-C"), "lan");
    BOOST_CHECK(eng.bit_of("P2P-SCN-C"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-C", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-C"), "lan");
    BOOST_CHECK(eng.bit_of("P2P-SCN-C"));
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-C"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_D)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-D"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-D"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-D"));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-D"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(eng.Apply("P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-D"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-D"), "1");
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.Apply("P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-D"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK(!eng.Apply("P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-D"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-D"), "1");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-D"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_E)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-E", "lose", "seed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-E"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-E"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-E"));
    BOOST_CHECK(eng.Apply("P2P-SCN-E", "", "seed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-E"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-E"), "seed");
    BOOST_CHECK(!eng.Apply("P2P-SCN-E", "lose", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-E"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-E"), "seed");
    BOOST_CHECK(!eng.Apply("P2P-SCN-E", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-E"), "seed");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-E"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_F)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-F", "", "cloud", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-F"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-F"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-F"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-F", "", "xcloudy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-F"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("P2P-SCN-F", "", "peers", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-F"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-F"), "peers");
    BOOST_CHECK(!eng.Apply("P2P-SCN-F", "", "cloud", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-F"), "peers");
    BOOST_CHECK(!eng.Apply("P2P-SCN-F", "", "peers", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-F"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-F"), "peers");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-F"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_G)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-G", "", "api-key", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "API");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-G"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-G"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-G"));
    BOOST_CHECK(eng.Apply("P2P-SCN-G", "", "memory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-G"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-G"), "memory");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Apply("P2P-SCN-G", "", "k-api-key-z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "API");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-G"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-G"), "memory");
    BOOST_CHECK(!eng.Apply("P2P-SCN-G", "", "memory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-G"), "memory");
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-G"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_H)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-H", "", "nixl", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-H"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-H"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-H"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-H", "", "mooncake", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-H"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-H", "", "rdma", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-H"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("P2P-SCN-H", "", "local-kv", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-H"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-H"), "local-kv");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-H", "", "nixl", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-H"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-H"), "local-kv");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-H", "", "local-kv", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-H"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-H"), "local-kv");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-H"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_I)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-I", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-I"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-I"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-I"));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-I", "train", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-I"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-I"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_P2P_SCN_J)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("P2P-SCN-J", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-J"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-J"), "");
    BOOST_CHECK(!eng.bit_of("P2P-SCN-J"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-J", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-J"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-J", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-J"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("P2P-SCN-J", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-J"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-J"), "left,right");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK(!eng.Apply("P2P-SCN-J", "", "left", "other", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-J"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-J"), "left,right");
    BOOST_CHECK(!eng.Apply("P2P-SCN-J", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-J"), "left,right");
    BOOST_CHECK(!eng.Apply("P2P-SCN-J", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-J"), "left,right");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-J"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp23 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NO-SUCH", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NO-SUCH"), "");
    BOOST_CHECK_EQUAL(eng.classification("NO-SUCH"), "COMPONENT");
    BOOST_CHECK(!eng.Apply("P2P-NOPE", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("P2P-NOPE"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("P2P-NOPE"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
