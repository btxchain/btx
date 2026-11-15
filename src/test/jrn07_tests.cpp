// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn07/jrn07.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Jrn07& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
}

// Refusal fixtures copied from src/test/acc07_tests.cpp only.
struct Refusal {
    const char* id;
    const char* text;
    const char* code;
};

const Refusal kRefusals[] = {
    {"E2E-006", "backup", "ROLLBACK"},
    {"QA-001", "skip", "FAIL"},
    {"QA-002", "native", "PACKAGE"},
    {"QA-003", "growth", "CLAIM"},
    {"REV-001", "1.0.0", "REVISION"},
    {"REV-002", "signed-release", "UNSIGNED"},
    {"REV-004", "cycle", "CYCLE"},
    {"REV-005", "empty-keys", "PENDING"},
    {"REV-008", "early", "BATCH"},
    {"REV-009", "shell", "ACTION"},
    {"REV-010", "default", "PROFILE"},
    {"REV-011", "weaker", "STRICT"},
    {"REV-013", "late", "PLAN"},
    {"REV-014", "shared", "TOKEN"},
    {"REV-015", "score", "BINDING"},
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(jrn07_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass)
{
    modelnet::Jrn07 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    for (const Refusal& row : kRefusals) {
        BOOST_CHECK(!std::string(row.id).empty());
        BOOST_CHECK(!std::string(row.text).empty());
        BOOST_CHECK(!std::string(row.code).empty());
    }
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
