// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nt04/nt04.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Nt04& eng)
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
}

struct KnownRow {
    const char* id;
    bool unqualified;
    bool spend_only;
};

const KnownRow kKnown[] = {
    {"NT-DATA-005", false, false},
    {"NT-ECON-001", false, false},
    {"NT-ECON-002", false, false},
    {"NT-ECON-003", false, false},
    {"NT-ECON-004", false, true},
    {"NT-QA-001", false, false},
    {"NT-QA-002", false, false},
    {"NT-QA-003", false, false},
    {"NT-QA-004", false, false},
    {"NT-QA-005", false, false},
    {"NT-QA-006", false, false},
    {"NT-QA-007", true, false},
    {"NT-GOV-001", false, false},
    {"NT-GOV-002", false, false},
    {"NT-GOV-003", false, false},
    {"NT-GOV-004", false, true},
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(nt04_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Nt04 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("NT-NO-SUCH", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("NT-NO-SUCH"));

    BOOST_CHECK(!eng.Apply("NT-DATA-005", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("NT-DATA-005"));

    BOOST_CHECK(!eng.Apply("NT-DATA-005", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("NT-DATA-005"));

    BOOST_CHECK(!eng.Apply("NT-DATA-005", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("NT-DATA-005"));

    BOOST_CHECK(!eng.Apply("NT-DATA-005", "s1", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("NT-DATA-005"));

    BOOST_CHECK(eng.Apply("NT-DATA-005", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("NT-DATA-005"));
    BOOST_CHECK_EQUAL(eng.text("NT-DATA-005"), "s1");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(exact_engine_private_qa_and_spend)
{
    modelnet::Nt04 eng;
    std::string err = "stale";
    const char* const exact[] = {
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
    BOOST_CHECK(!modelnet::NifDtEngineLinked("dualpipe"));

    for (const char* name : exact) {
        BOOST_CHECK(!eng.Apply("NT-ECON-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("NT-ECON-001"));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.gpu_passed());
        BOOST_CHECK(!eng.windows_passed());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(eng.Apply("NT-ECON-002", "deepep", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("NT-ECON-002"));
    BOOST_CHECK_EQUAL(eng.text("NT-ECON-002"), "deepep");

    BOOST_CHECK(!eng.Apply("NT-ECON-001", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("NT-ECON-001"));

    BOOST_CHECK(!eng.Apply("NT-QA-007", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("NT-QA-007", "s1", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NT-QA-007", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NT-QA-007", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Apply("NT-QA-007", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.Apply("NT-QA-007", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("NT-QA-007"));
    BOOST_CHECK(!eng.Apply("NT-QA-007", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("NT-QA-007"));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");

    BOOST_CHECK(!eng.Apply("NT-ECON-004", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("NT-ECON-004", "s1", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NT-ECON-004", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NT-ECON-004", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.stored("NT-ECON-004"));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Apply("NT-ECON-004", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.stored("NT-ECON-004"));

    BOOST_CHECK(!eng.Apply("NT-GOV-004", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.stored("NT-GOV-004"));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_release_stays_unqualified)
{
    modelnet::Nt04 eng;
    std::string err = "stale";

    for (const KnownRow& row : kKnown) {
        if (row.unqualified) {
            BOOST_CHECK(!eng.Apply(row.id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.stored(row.id));
            BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
            continue;
        }
        if (row.spend_only) {
            BOOST_CHECK(!eng.Apply(row.id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
            BOOST_CHECK_EQUAL(err, "0");
            BOOST_CHECK(!eng.stored(row.id));
            BOOST_CHECK(!eng.broadcast());
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            continue;
        }
        BOOST_CHECK(eng.Apply(row.id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(row.id));
        BOOST_CHECK_EQUAL(eng.text(row.id), "s1");
        BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        BOOST_CHECK(!eng.Apply(row.id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(row.id), "s1");
        BOOST_CHECK(!eng.Apply(row.id, "s2", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(row.id), "s1");
    }

    BOOST_CHECK(eng.stored("NT-QA-001"));
    BOOST_CHECK(eng.stored("NT-QA-002"));
    BOOST_CHECK(eng.stored("NT-QA-003"));
    BOOST_CHECK(eng.stored("NT-QA-004"));
    BOOST_CHECK(eng.stored("NT-QA-005"));
    BOOST_CHECK(eng.stored("NT-QA-006"));
    BOOST_CHECK_EQUAL(eng.text("NT-QA-006"), "s1");
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.stored("NT-QA-007"));
    BOOST_CHECK(!eng.stored("NT-ECON-004"));
    BOOST_CHECK(!eng.stored("NT-GOV-004"));

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
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Nt04 eng;
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
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
