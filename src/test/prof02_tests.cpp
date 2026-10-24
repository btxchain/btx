// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prof02/prof02.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Prof02& eng)
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
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
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
}

const char* const kKnown[] = {
    "DT-Q01",
    "DT-Q02",
    "DT-Q03",
    "DT-Q04",
    "DT-Q05",
    "DT-Q06",
    "DT-Q07",
    "DT-Q08",
    "DT-Q09",
    "DT-Q10",
    "DT-Q11",
    "DT-Q12",
    "DT-Q13",
    "DT-Q14",
    "DT-Q15",
    "DT-Q16",
    "DT-Q17",
    "DT-Q18",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(prof02_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Prof02 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("DT-NO-SUCH", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-NO-SUCH"));

    BOOST_CHECK(!eng.Apply("DT-Q00", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-Q00"));

    BOOST_CHECK(!eng.Apply("DT-Q19", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-Q19"));

    BOOST_CHECK(!eng.Apply("DT-Q01", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DT-Q01"));

    BOOST_CHECK(!eng.Apply("DT-Q01", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DT-Q01"));

    BOOST_CHECK(!eng.Apply("DT-Q01", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DT-Q01"));

    BOOST_CHECK(!eng.Apply("DT-Q01", "s1", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DT-Q01"));

    BOOST_CHECK(!eng.Apply("DT-Q04", "rdma", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DT-Q04"));

    BOOST_CHECK(!eng.Apply("DT-Q07", "fp8", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DT-Q07"));

    BOOST_CHECK(!eng.Apply("DT-Q01", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("DT-Q01"));
    BOOST_CHECK(eng.text("DT-Q01").empty());

    BOOST_CHECK(!eng.Apply("DT-Q01", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("DT-Q01"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engine_exact_and_private)
{
    modelnet::Prof02 eng;
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
    BOOST_CHECK(!modelnet::NifDtEngineLinked("dualpipe"));

    for (const char* name : engines) {
        BOOST_CHECK(!eng.Apply("DT-Q02", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("DT-Q02"));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("DT-Q04", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(err != std::string("NOT_RUN"));
    BOOST_CHECK(!eng.stored("DT-Q04"));
    BOOST_CHECK(!eng.broadcast());

    BOOST_CHECK(!eng.Apply("DT-Q07", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(err != std::string("NOT_RUN"));
    BOOST_CHECK(!eng.stored("DT-Q07"));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());

    BOOST_CHECK(!eng.Apply("DT-Q02", "deepep", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("DT-Q02"));

    BOOST_CHECK(!eng.Apply("DT-Q02", "vllm-extra", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("DT-Q02"));

    BOOST_CHECK(!eng.Apply("DT-Q02", "private trajectory", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DT-Q02"));

    BOOST_CHECK(!eng.Apply("DT-Q03", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DT-Q03"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_stays_not_run)
{
    modelnet::Prof02 eng;
    std::string err = "stale";

    for (const char* id : kKnown) {
        if (std::string(id) == "DT-Q04") {
            BOOST_CHECK(!eng.Apply(id, "rdma", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
            BOOST_CHECK(!eng.stored(id));
        }
        if (std::string(id) == "DT-Q07") {
            BOOST_CHECK(!eng.Apply(id, "fp8", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK(!eng.gpu_passed());
        }
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "NOT_RUN");
        BOOST_CHECK(!eng.stored(id));
        BOOST_CHECK(eng.text(id).empty());
        BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK(!eng.release_qualified());
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "NOT_RUN");
        BOOST_CHECK(!eng.stored(id));
        if (std::string(id) == "DT-Q12") {
            BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.stored("DT-Q12"));
            BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        }
    }

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
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
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    for (const char* id : kKnown) {
        BOOST_CHECK(!eng.stored(id));
    }
    BOOST_CHECK(!eng.stored("DT-Q19"));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Prof02 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DT-Q12", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("DT-Q12"));
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
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
