// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp04/grp04.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp04& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp04_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(req_NIF_DATA_004)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-DATA-004", "remote", "hi", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "DOWNLOAD");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-004"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-004", "", "hi", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-004"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-004", "", "PYTHON_PICKLE", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-004"));
    BOOST_CHECK(eng.Apply("NIF-DATA-004", "", "hi", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-004"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-004"), "hi");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-DATA-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_DATA_005)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-DATA-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CASE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-005"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-005", "pin1", "private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-005"));
    BOOST_CHECK(eng.Apply("NIF-DATA-005", "pin1", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-DATA-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-DATA-005"), "public");
    BOOST_CHECK(!eng.bit_of("NIF-DATA-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-DATA-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ECON_001)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("NIF-ECON-001", "draft", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-001"), "draft");
    BOOST_CHECK(!eng.bit_of("NIF-ECON-001"));
    BOOST_CHECK(eng.Apply("NIF-ECON-001", "accept", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-001"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-001"), "accepted");
    BOOST_CHECK(eng.bit_of("NIF-ECON-001"));
    BOOST_CHECK(!eng.Apply("NIF-ECON-001", "accept", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-001"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-001"), "accepted");
    BOOST_CHECK(eng.bit_of("NIF-ECON-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ECON-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ECON_002)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-ECON-002", "", "", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "OVER");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-ECON-002"));
    BOOST_CHECK(eng.Apply("NIF-ECON-002", "", "", "", static_cast<int64_t>(15), static_cast<int64_t>(10), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-002"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-002"), "quote");
    BOOST_CHECK(!eng.bit_of("NIF-ECON-002"));
    BOOST_CHECK(!eng.Apply("NIF-ECON-002", "", "", "", static_cast<int64_t>(15), static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-002"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-002"), "quote");
    BOOST_CHECK(!eng.bit_of("NIF-ECON-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ECON-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ECON_003)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-ECON-003", "pay", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-ECON-003"));
    BOOST_CHECK(!eng.Apply("NIF-ECON-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-003"), "");
    BOOST_CHECK(eng.bit_of("NIF-ECON-003"));
    BOOST_CHECK(!eng.Apply("NIF-ECON-003", "pay", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-003"), "");
    BOOST_CHECK(eng.bit_of("NIF-ECON-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ECON-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_ECON_004)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-ECON-004", "", "wallet", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "WALLET");
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-ECON-004"));
    BOOST_CHECK(eng.Apply("NIF-ECON-004", "", "research", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-ECON-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ECON-004"), "research");
    BOOST_CHECK(!eng.bit_of("NIF-ECON-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-ECON-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_002)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-002", "", "hardware", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-002"));
    BOOST_CHECK(eng.Apply("NIF-QA-002", "", "fixture", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-002"), "fixture");
    BOOST_CHECK(!eng.bit_of("NIF-QA-002"));
    BOOST_CHECK(eng.Apply("NIF-QA-002", "", "useful", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-002"), "useful");
    BOOST_CHECK(!eng.bit_of("NIF-QA-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_003)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-003", "", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-003"));
    BOOST_CHECK(eng.Apply("NIF-QA-003", "", "batch", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-003"), "batch");
    BOOST_CHECK(!eng.bit_of("NIF-QA-003"));
    BOOST_CHECK(eng.Apply("NIF-QA-003", "", "stochastic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-003"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-003"), "stochastic");
    BOOST_CHECK(!eng.bit_of("NIF-QA-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_004)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-004", "", "fast", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-004"));
    BOOST_CHECK(eng.Apply("NIF-QA-004", "", "cold", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-004"), "cold");
    BOOST_CHECK(!eng.bit_of("NIF-QA-004"));
    BOOST_CHECK(eng.Apply("NIF-QA-004", "", "remote", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-004"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-004"), "remote");
    BOOST_CHECK(!eng.bit_of("NIF-QA-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_005)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-005", "", "bench", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-005"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-005"));
    BOOST_CHECK(eng.Apply("NIF-QA-005", "", "privacy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-005"), "privacy");
    BOOST_CHECK(!eng.bit_of("NIF-QA-005"));
    BOOST_CHECK(eng.Apply("NIF-QA-005", "", "failure", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-005"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-005"), "failure");
    BOOST_CHECK(!eng.bit_of("NIF-QA-005"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_006)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-006"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-006"));
    BOOST_CHECK(eng.Apply("NIF-QA-006", "", "src", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-006"), "src");
    BOOST_CHECK(!eng.bit_of("NIF-QA-006"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_007)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-007", "", "release", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-007"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-007"));
    BOOST_CHECK(!eng.Apply("NIF-QA-007", "promote", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-007"), "");
    BOOST_CHECK(!eng.bit_of("NIF-QA-007"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-007"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_GOV_001)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-GOV-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-001"), "");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-001"));
    BOOST_CHECK(eng.Apply("NIF-GOV-001", "", "grok-4.7-high", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-001"), "grok-4.7-high");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-001"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-GOV-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_GOV_002)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-GOV-002", "public", "spec", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PUBLIC");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-002"), "");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-002"));
    BOOST_CHECK(eng.Apply("NIF-GOV-002", "", "private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-002"), "private");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-002"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-GOV-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_GOV_003)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-GOV-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-003"), "");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-003"));
    BOOST_CHECK(eng.Apply("NIF-GOV-003", "", "w41", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-003"), "w41");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-003"));
    BOOST_CHECK(!eng.Apply("NIF-GOV-003", "", "w42", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-003"), "w41");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-003"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-GOV-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_GOV_004)
{
    modelnet::Grp04 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-GOV-004", "publish", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-004"));
    BOOST_CHECK(!eng.Apply("NIF-GOV-004", "push", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-004"), "");
    BOOST_CHECK(!eng.bit_of("NIF-GOV-004"));
    BOOST_CHECK_EQUAL(eng.classification("NIF-GOV-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()

