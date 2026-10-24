// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp05/grp05.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp05& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp05_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_DT_EVD_001)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-001", "", "hardware", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-001"));
    BOOST_CHECK(eng.Apply("DT-EVD-001", "", "documented", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-001"), "documented");
    BOOST_CHECK(!eng.bit_of("DT-EVD-001"));
    BOOST_CHECK(eng.Apply("DT-EVD-001", "", "hypothesis", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-001"), "hypothesis");
    BOOST_CHECK(!eng.bit_of("DT-EVD-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_EVD_002)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BASELINE");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-002"));
    BOOST_CHECK(eng.Apply("DT-EVD-002", "", "b1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-002"), "b1");
    BOOST_CHECK(!eng.bit_of("DT-EVD-002"));
    BOOST_CHECK(!eng.Apply("DT-EVD-002", "", "b2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ALTERED");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-002"), "b1");
    BOOST_CHECK(!eng.bit_of("DT-EVD-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_EVD_003)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-003", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PIN");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-003"));
    BOOST_CHECK(eng.Apply("DT-EVD-003", "", "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-003"), "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01");
    BOOST_CHECK(!eng.bit_of("DT-EVD-003"));
    BOOST_CHECK(!eng.Apply("DT-EVD-003", "replace", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLACE");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-003"), "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01");
    BOOST_CHECK(!eng.bit_of("DT-EVD-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_EVD_004)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-004"));
    BOOST_CHECK(eng.Apply("DT-EVD-004", "", "grok-4.7-high", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-004"), "grok-4.7-high");
    BOOST_CHECK(!eng.bit_of("DT-EVD-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_EVD_005)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-005", "git", "spec", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-005"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-005"));
    BOOST_CHECK(eng.Apply("DT-EVD-005", "", "outside", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-005"), "outside");
    BOOST_CHECK(!eng.bit_of("DT-EVD-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_EVD_006)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-006", "", "pass", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-006"));
    BOOST_CHECK(eng.Apply("DT-EVD-006", "", "hardware", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-006"), "hardware");
    BOOST_CHECK(!eng.bit_of("DT-EVD-006"));
    BOOST_CHECK(eng.Apply("DT-EVD-006", "", "release", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-006"), "release");
    BOOST_CHECK(!eng.bit_of("DT-EVD-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_EVD_007)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ATTRIBUTION");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-007"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-007"));
    BOOST_CHECK(eng.Apply("DT-EVD-007", "", "DeepSeek", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-007"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-007"), "DeepSeek");
    BOOST_CHECK(!eng.bit_of("DT-EVD-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_EVD_008)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-EVD-008", "", "complete", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNINSPECTED");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-EVD-008"));
    BOOST_CHECK(eng.Apply("DT-EVD-008", "", "uninspected", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-008"), "uninspected");
    BOOST_CHECK(!eng.bit_of("DT-EVD-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_001)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-NAT-001", "sidecar", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-001"));
    BOOST_CHECK(!eng.Apply("DT-NAT-001", "btxd", "extra", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FLAG");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-001"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-001"));
    BOOST_CHECK(eng.Apply("DT-NAT-001", "btxd", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-001"), "btxd");
    BOOST_CHECK(!eng.bit_of("DT-NAT-001"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_002)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-NAT-002", "", "c1", "", static_cast<int64_t>(10), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-002"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-002"));
    BOOST_CHECK(eng.Apply("DT-NAT-002", "", "c1", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-002"), "c1");
    BOOST_CHECK(!eng.bit_of("DT-NAT-002"));
    BOOST_CHECK(eng.Apply("DT-NAT-002", "commit", "c1", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-002"), "c1");
    BOOST_CHECK(eng.bit_of("DT-NAT-002"));
    BOOST_CHECK(!eng.Apply("DT-NAT-002", "commit", "c1", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-002"), "c1");
    BOOST_CHECK(eng.bit_of("DT-NAT-002"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_003)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-NAT-003", "", "c1", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-003"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-003"));
    BOOST_CHECK(eng.Apply("DT-NAT-003", "", "c1", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-003"), "c1");
    BOOST_CHECK(!eng.bit_of("DT-NAT-003"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_004)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-NAT-004", "schedule", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-004"));
    BOOST_CHECK(!eng.Apply("DT-NAT-004", "reserve", "", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-004"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-004"));
    BOOST_CHECK(eng.Apply("DT-NAT-004", "reserve", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-004"), "reserved");
    BOOST_CHECK(!eng.bit_of("DT-NAT-004"));
    BOOST_CHECK(eng.Apply("DT-NAT-004", "schedule", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-004"), "reserved");
    BOOST_CHECK(eng.bit_of("DT-NAT-004"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_005)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-NAT-005", "reserve", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-005"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-005"), "held");
    BOOST_CHECK(!eng.bit_of("DT-NAT-005"));
    BOOST_CHECK(eng.Apply("DT-NAT-005", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-005"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-005"), "held");
    BOOST_CHECK(eng.bit_of("DT-NAT-005"));
    BOOST_CHECK(!eng.Apply("DT-NAT-005", "release", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-005"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-005"), "held");
    BOOST_CHECK(eng.bit_of("DT-NAT-005"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_006)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-NAT-006", "publish", "ced", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-006"));
    BOOST_CHECK(!eng.Apply("DT-NAT-006", "publish", "dense", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-006"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-006"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_007)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DT-NAT-007", "stage", "w", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-007"), "staged");
    BOOST_CHECK(!eng.bit_of("DT-NAT-007"));
    BOOST_CHECK(!eng.Apply("DT-NAT-007", "commit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-007"), "staged");
    BOOST_CHECK(!eng.bit_of("DT-NAT-007"));
    BOOST_CHECK(eng.Apply("DT-NAT-007", "commit", "w", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-007"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-007"), "w");
    BOOST_CHECK(!eng.bit_of("DT-NAT-007"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_NAT_008)
{
    modelnet::Grp05 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-NAT-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "API");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-008"));
    BOOST_CHECK(!eng.Apply("DT-NAT-008", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-008"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-008"), "");
    BOOST_CHECK(!eng.bit_of("DT-NAT-008"));
    BOOST_CHECK(eng.Apply("DT-NAT-008", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-008"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-008"), "local");
    BOOST_CHECK(!eng.bit_of("DT-NAT-008"));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-008"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

