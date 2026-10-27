// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nt01/nt01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Nt01& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
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
    BOOST_CHECK(!eng.gpu_passed());
}

const char* const kKnown[] = {
    "NT-NAT-001",
    "NT-NAT-002",
    "NT-NAT-003",
    "NT-NAT-004",
    "NT-NAT-005",
    "NT-NAT-006",
    "NT-FORK-001",
    "NT-FORK-002",
    "NT-FORK-003",
    "NT-FORK-004",
    "NT-FORK-005",
    "NT-FORK-006",
    "NT-PROF-001",
    "NT-PROF-002",
    "NT-PROF-003",
    "NT-PROF-004",
    "NT-PROF-005",
    "NT-PROF-006",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(nt01_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Nt01 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("NT-NO-SUCH", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("NT-NO-SUCH"));

    BOOST_CHECK(!eng.Apply("NT-NAT-007", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("NT-NAT-007"));

    BOOST_CHECK(!eng.Apply("NT-NAT-001", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("NT-NAT-001"));

    BOOST_CHECK(!eng.Apply("NT-NAT-001", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("NT-NAT-001"));

    BOOST_CHECK(!eng.Apply("NT-NAT-001", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("NT-NAT-001"));

    BOOST_CHECK(!eng.Apply("NT-NAT-001", "s1", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("NT-NAT-001"));

    BOOST_CHECK(eng.Apply("NT-NAT-001", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("NT-NAT-001"));
    BOOST_CHECK_EQUAL(eng.text("NT-NAT-001"), "s1");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engine_private_fork_and_prof)
{
    modelnet::Nt01 eng;
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
    BOOST_CHECK(!eng.Apply("NT-NAT-002", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.stored("NT-NAT-002"));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());

    BOOST_CHECK(!modelnet::NifDtEngineLinked("dualpipe"));
    BOOST_CHECK(!eng.Apply("NT-NAT-002", "dualpipe", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("NT-NAT-002"));

    for (const char* name : engines) {
        BOOST_CHECK(!eng.Apply("NT-NAT-002", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK(!eng.stored("NT-NAT-002"));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("NT-NAT-002", "private trajectory", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("NT-NAT-002"));

    BOOST_CHECK(!eng.Apply("NT-FORK-004", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("NT-FORK-004", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("NT-FORK-004", "s1", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NT-FORK-004", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NT-FORK-004", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.Apply("NT-FORK-004", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.stored("NT-FORK-004"));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Apply("NT-FORK-005", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("NT-FORK-005"));
    BOOST_CHECK(!eng.Apply("NT-FORK-005", "s2", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("NT-FORK-005"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");

    BOOST_CHECK(!eng.Apply("NT-PROF-006", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("NT-PROF-006", "gpu", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("NT-PROF-006", "gpu", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NT-PROF-006", "gpu", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NT-PROF-006", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Apply("NT-PROF-006", "gpu", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("NT-PROF-006"));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.Apply("NT-PROF-006", "gpu", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("NT-PROF-006"));

    BOOST_CHECK(eng.Apply("NT-NAT-002", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("NT-NAT-002"));
    BOOST_CHECK_EQUAL(eng.text("NT-NAT-002"), "s1");
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_release_stays_unqualified)
{
    modelnet::Nt01 eng;
    std::string err = "stale";

    for (const char* id : kKnown) {
        if (std::string(id) == "NT-FORK-004" || std::string(id) == "NT-FORK-005") {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text(id), "");
            BOOST_CHECK(!eng.broadcast());
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
            BOOST_CHECK(!eng.gpu_passed());
            continue;
        }
        if (std::string(id) == "NT-PROF-006") {
            BOOST_CHECK(!eng.Apply(id, "gpu", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK(!eng.gpu_passed());
            BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        }
        BOOST_CHECK(eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        BOOST_CHECK(!eng.gpu_passed());
        BOOST_CHECK(!eng.windows_passed());
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        if (std::string(id) == "NT-PROF-006") {
            BOOST_CHECK(!eng.Apply(id, "gpu", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(eng.text(id), "s1");
            BOOST_CHECK(!eng.gpu_passed());
            BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        }
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
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.stored("NT-NAT-001"));
    BOOST_CHECK_EQUAL(eng.text("NT-NAT-006"), "s1");
    BOOST_CHECK(eng.stored("NT-FORK-001"));
    BOOST_CHECK_EQUAL(eng.text("NT-FORK-006"), "s1");
    BOOST_CHECK(!eng.stored("NT-FORK-004"));
    BOOST_CHECK(!eng.stored("NT-FORK-005"));
    BOOST_CHECK(eng.stored("NT-PROF-006"));
    BOOST_CHECK_EQUAL(eng.text("NT-PROF-006"), "s1");
    BOOST_CHECK(!eng.stored("NT-NAT-007"));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Nt01 eng;
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
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
