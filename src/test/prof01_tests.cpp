// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prof01/prof01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Prof01& eng)
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
}

const char* const kKnown[] = {
    "fresh-native-start",
    "local-cpu-useful-model",
    "linux-sm100-deepinfer",
    "linux-ascend-deepinfer",
    "macos-portable",
    "windows-portable",
    "lan-two-physical-hosts",
    "wan-three-native-peers",
    "private-case-revocation",
    "deepinfer-exact-multirank-state",
    "whole-node-airgap",
    "offline-runtime-image",
    "economic-regtest",
    "failure-and-rollback",
};

const char* const kEngines[] = {
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(prof01_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Prof01 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK(eng.text("").empty());

    BOOST_CHECK(!eng.Apply("no-such", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("no-such"));

    BOOST_CHECK(!eng.Apply("no-such", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("no-such"));

    BOOST_CHECK(!eng.Apply("fresh-native-start", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("fresh-native-start"));

    BOOST_CHECK(!eng.Apply("fresh-native-start", "s1", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("fresh-native-start"));

    BOOST_CHECK(!eng.Apply("fresh-native-start", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("fresh-native-start"));

    BOOST_CHECK(!eng.Apply("fresh-native-start", "s1", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("fresh-native-start"));

    BOOST_CHECK(!eng.Apply("fresh-native-start", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("fresh-native-start"));
    BOOST_CHECK(eng.text("fresh-native-start").empty());

    BOOST_CHECK(!eng.Apply("fresh-native-start", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("fresh-native-start"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(exact_engine_and_private)
{
    modelnet::Prof01 eng;
    std::string err = "stale";

    BOOST_CHECK(modelnet::NifDtEngineLinked("fp8"));
    BOOST_CHECK(modelnet::NifDtEngineLinked("fp4"));
    for (const char* name : kEngines) {
        BOOST_CHECK(!eng.Apply("local-cpu-useful-model", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("local-cpu-useful-model"));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.gpu_passed());
    }

    BOOST_CHECK(!modelnet::NifDtEngineLinked("deepep"));
    BOOST_CHECK(!eng.Apply("local-cpu-useful-model", "deepep", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("local-cpu-useful-model"));

    BOOST_CHECK(!eng.Apply("local-cpu-useful-model", "vllm-extra", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("local-cpu-useful-model"));

    BOOST_CHECK(!eng.Apply("fresh-native-start", "private trajectory", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("fresh-native-start"));

    BOOST_CHECK(!eng.Apply("private-case-revocation", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("private-case-revocation"));

    BOOST_CHECK(!eng.Apply("private-case-revocation", "private trajectory", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.stored("private-case-revocation"));
    BOOST_CHECK(eng.text("private-case-revocation").empty());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_stays_not_run)
{
    modelnet::Prof01 eng;
    std::string err = "stale";

    for (const char* id : kKnown) {
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "NOT_RUN");
        BOOST_CHECK(!eng.stored(id));
        BOOST_CHECK(eng.text(id).empty());
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "NOT_RUN");
        BOOST_CHECK(!eng.stored(id));
        BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        BOOST_CHECK(!eng.gpu_passed());
        BOOST_CHECK(!eng.windows_passed());
        BOOST_CHECK(!eng.launched());
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.broadcast());
        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("windows-portable", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.stored("windows-portable"));

    BOOST_CHECK(!eng.Apply("macos-portable", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.stored("macos-portable"));

    BOOST_CHECK(!eng.Apply("linux-sm100-deepinfer", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK(!eng.stored("linux-sm100-deepinfer"));

    BOOST_CHECK(!eng.Apply("linux-sm100-deepinfer", "deepinfer", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("linux-sm100-deepinfer"));
    BOOST_CHECK(!eng.gpu_passed());

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
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    for (const char* id : kKnown) {
        BOOST_CHECK(!eng.stored(id));
    }
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Prof01 eng;
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
