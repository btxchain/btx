// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dtat03/dtat03.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Dtat03& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
}

const char* const kIds[] = {
    "DT-AT-OPT-001",
    "DT-AT-OPT-002",
    "DT-AT-OPT-003",
    "DT-AT-OPT-004",
    "DT-AT-OPT-005",
    "DT-AT-OPT-006",
    "DT-AT-OPT-007",
    "DT-AT-OPT-008",
    "DT-AT-DAT-001",
    "DT-AT-DAT-002",
    "DT-AT-DAT-003",
    "DT-AT-DAT-004",
    "DT-AT-DAT-005",
    "DT-AT-DAT-006",
    "DT-AT-DAT-007",
    "DT-AT-DAT-008",
};

bool UnqualifiedId(const char* id)
{
    return std::string(id) == "DT-AT-OPT-005" || std::string(id) == "DT-AT-OPT-006";
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dtat03_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Dtat03 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("DT-NO-SUCH", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-NO-SUCH"));

    BOOST_CHECK(!eng.Apply("DT-AT-OPT-009", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-AT-OPT-009"));

    BOOST_CHECK(!eng.Apply("DT-AT-DAT-009", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-AT-DAT-009"));

    BOOST_CHECK(!eng.Apply("DT-AT-OPT-001", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DT-AT-OPT-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-OPT-001", "s1", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DT-AT-OPT-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-OPT-001", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DT-AT-OPT-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-OPT-001", "fp8", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DT-AT-OPT-001"));

    BOOST_CHECK(eng.Apply("DT-AT-OPT-001", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DT-AT-OPT-001"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-OPT-001"), "s1");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engine_finite_private_and_unqualified)
{
    modelnet::Dtat03 eng;
    std::string err = "stale";
    const char* const engines[] = {
        "vllm",
        "sglang",
        "lmcache",
        "nixl",
        "mooncake",
        "rdma",
        "deepinfer",
        "dualpipe",
        "fp8",
        "fp4",
    };

    BOOST_CHECK(modelnet::NifDtEngineLinked("fp8"));
    BOOST_CHECK(modelnet::NifDtEngineLinked("fp4"));
    for (const char* name : engines) {
        BOOST_CHECK(!eng.Apply("DT-AT-DAT-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("DT-AT-DAT-001"));
        BOOST_CHECK_EQUAL(eng.text("DT-AT-DAT-001"), "");
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.gpu_passed());
    }

    BOOST_CHECK(!eng.Apply("DT-AT-DAT-002", "nan", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(!eng.stored("DT-AT-DAT-002"));
    BOOST_CHECK(!eng.Apply("DT-AT-DAT-002", "inf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(!eng.Apply("DT-AT-DAT-002", "s1nan", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(!eng.Apply("DT-AT-DAT-002", "s1inf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(!eng.Apply("DT-AT-DAT-002", "nan private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.text("DT-AT-DAT-002"), "");
    BOOST_CHECK(!eng.stored("DT-AT-DAT-002"));

    BOOST_CHECK(!eng.Apply("DT-AT-DAT-003", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DT-AT-DAT-003"));
    BOOST_CHECK(!eng.Apply("DT-AT-DAT-003", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.text("DT-AT-DAT-003"), "");

    BOOST_CHECK(!eng.Apply("DT-AT-OPT-005", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("DT-AT-OPT-005", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("DT-AT-OPT-005", "nan", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(!eng.Apply("DT-AT-OPT-006", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DT-AT-OPT-005"));
    BOOST_CHECK(!eng.stored("DT-AT-OPT-006"));

    BOOST_CHECK(!eng.Apply("DT-AT-OPT-005", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DT-AT-OPT-005"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-OPT-005"), "");
    BOOST_CHECK(!eng.Apply("DT-AT-OPT-005", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("DT-AT-OPT-005"));
    BOOST_CHECK(!eng.Apply("DT-AT-OPT-006", "s2", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("DT-AT-OPT-006"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-OPT-006"), "");
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.windows_passed());

    BOOST_CHECK(eng.Apply("DT-AT-DAT-004", "fp48", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DT-AT-DAT-004"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-DAT-004"), "fp48");
    BOOST_CHECK(!eng.Apply("DT-AT-DAT-004", "s1inf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.text("DT-AT-DAT-004"), "fp48");
    BOOST_CHECK(!eng.Apply("DT-AT-DAT-004", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(eng.text("DT-AT-DAT-004"), "fp48");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_release_stays_unqualified)
{
    modelnet::Dtat03 eng;
    std::string err = "stale";

    for (const char* id : kIds) {
        if (UnqualifiedId(id)) {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text(id), "");
            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK(!eng.broadcast());
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            continue;
        }
        BOOST_CHECK(eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(0), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(100), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    }

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(eng.stored("DT-AT-OPT-001"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-OPT-001"), "s1");
    BOOST_CHECK(eng.stored("DT-AT-DAT-008"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-DAT-008"), "s1");
    BOOST_CHECK(!eng.stored("DT-AT-OPT-005"));
    BOOST_CHECK(!eng.stored("DT-AT-OPT-006"));
    BOOST_CHECK(!eng.stored("DT-AT-OPT-009"));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Dtat03 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
