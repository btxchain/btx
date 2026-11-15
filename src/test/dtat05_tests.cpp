// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dtat05/dtat05.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Dtat05& eng)
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
    "DT-AT-WAN-001",
    "DT-AT-WAN-002",
    "DT-AT-WAN-003",
    "DT-AT-WAN-004",
    "DT-AT-WAN-005",
    "DT-AT-WAN-006",
    "DT-AT-WAN-007",
    "DT-AT-WAN-008",
    "DT-AT-SEC-001",
    "DT-AT-SEC-002",
    "DT-AT-SEC-003",
    "DT-AT-SEC-004",
    "DT-AT-SEC-005",
    "DT-AT-SEC-006",
    "DT-AT-SEC-007",
    "DT-AT-SEC-008",
};

bool NoRoute(const char* id)
{
    return std::string(id) == "DT-AT-WAN-001";
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dtat05_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Dtat05 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("DT-NO-SUCH", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-NO-SUCH"));

    BOOST_CHECK(!eng.Apply("DT-AT-WAN-009", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-AT-WAN-009"));

    BOOST_CHECK(!eng.Apply("DT-AT-SEC-009", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-AT-SEC-009"));

    BOOST_CHECK(!eng.Apply("DT-AT-WAN-002", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DT-AT-WAN-002"));

    BOOST_CHECK(!eng.Apply("DT-AT-WAN-002", "s1", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DT-AT-WAN-002"));

    BOOST_CHECK(!eng.Apply("DT-AT-WAN-002", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DT-AT-WAN-002"));

    BOOST_CHECK(!eng.Apply("DT-AT-WAN-002", "fp8", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DT-AT-WAN-002"));

    BOOST_CHECK(eng.Apply("DT-AT-WAN-002", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DT-AT-WAN-002"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-WAN-002"), "s1");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engine_private_and_no_route)
{
    modelnet::Dtat05 eng;
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
        BOOST_CHECK(!eng.Apply("DT-AT-SEC-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("DT-AT-SEC-001"));
        BOOST_CHECK_EQUAL(eng.text("DT-AT-SEC-001"), "");
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.gpu_passed());
    }

    BOOST_CHECK(!eng.Apply("DT-AT-SEC-002", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DT-AT-SEC-002"));
    BOOST_CHECK(!eng.Apply("DT-AT-SEC-002", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.text("DT-AT-SEC-002"), "");

    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DT-AT-WAN-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK(!eng.stored("DT-AT-WAN-001"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-WAN-001"), "");
    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK(!eng.stored("DT-AT-WAN-001"));
    BOOST_CHECK(!eng.Apply("DT-AT-WAN-001", "s2", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK(!eng.stored("DT-AT-WAN-001"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-WAN-001"), "");
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.windows_passed());

    BOOST_CHECK(eng.Apply("DT-AT-WAN-007", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DT-AT-WAN-007"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-WAN-007"), "s1");
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");

    BOOST_CHECK(eng.Apply("DT-AT-SEC-003", "fp48", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DT-AT-SEC-003"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-SEC-003"), "fp48");
    BOOST_CHECK(!eng.Apply("DT-AT-SEC-003", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.text("DT-AT-SEC-003"), "fp48");
    BOOST_CHECK(!eng.Apply("DT-AT-SEC-003", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(eng.text("DT-AT-SEC-003"), "fp48");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_release_stays_unqualified)
{
    modelnet::Dtat05 eng;
    std::string err = "stale";

    for (const char* id : kIds) {
        if (NoRoute(id)) {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
            BOOST_CHECK_EQUAL(err, "NO_ROUTE");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text(id), "");
            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK(!eng.broadcast());
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
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
    BOOST_CHECK(eng.stored("DT-AT-WAN-002"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-WAN-002"), "s1");
    BOOST_CHECK(eng.stored("DT-AT-WAN-007"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-WAN-007"), "s1");
    BOOST_CHECK(eng.stored("DT-AT-SEC-008"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-SEC-008"), "s1");
    BOOST_CHECK(!eng.stored("DT-AT-WAN-001"));
    BOOST_CHECK(!eng.stored("DT-AT-WAN-009"));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Dtat05 eng;
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
