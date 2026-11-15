// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dtat04/dtat04.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Dtat04& eng)
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
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
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

const char* const kIds[] = {
    "DT-AT-RLP-001",
    "DT-AT-RLP-002",
    "DT-AT-RLP-003",
    "DT-AT-RLP-004",
    "DT-AT-RLP-005",
    "DT-AT-RLP-006",
    "DT-AT-RLP-007",
    "DT-AT-RLP-008",
    "DT-AT-CKP-001",
    "DT-AT-CKP-002",
    "DT-AT-CKP-003",
    "DT-AT-CKP-004",
    "DT-AT-CKP-005",
    "DT-AT-CKP-006",
    "DT-AT-CKP-007",
    "DT-AT-CKP-008",
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

BOOST_FIXTURE_TEST_SUITE(dtat04_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Dtat04 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("DT-NO-SUCH", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-NO-SUCH"));

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-009", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-009"));

    BOOST_CHECK(!eng.Apply("DT-AT-CKP-009", "pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-AT-CKP-009"));

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-001", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-001", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-001", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-001", "s1", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-001"));

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-006", "", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-006"));
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-006", "s1", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-006"));
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-006", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-006"));
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-006", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-006"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-006"), "");

    BOOST_CHECK(eng.Apply("DT-AT-RLP-001", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DT-AT-RLP-001"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-001"), "s1");
    BOOST_CHECK(eng.Apply("DT-AT-RLP-002", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-002"), "s1");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engine_pickle_private_and_ckpt)
{
    modelnet::Dtat04 eng;
    std::string err = "stale";

    for (const char* name : kEngines) {
        BOOST_CHECK(!eng.Apply("DT-AT-RLP-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("DT-AT-RLP-001"));
        BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-001"), "");
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.gpu_passed());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-006", "vllm", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-006"));
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-006", "pickle", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-006"));

    BOOST_CHECK(!eng.Apply("DT-AT-CKP-004", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("DT-AT-CKP-004"));
    BOOST_CHECK(!eng.Apply("DT-AT-CKP-004", "pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!eng.stored("DT-AT-CKP-004"));
    BOOST_CHECK(!eng.Apply("DT-AT-CKP-004", "private note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DT-AT-CKP-004"));
    BOOST_CHECK(!eng.Apply("DT-AT-CKP-004", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DT-AT-CKP-004"));
    BOOST_CHECK(!eng.Apply("DT-AT-CKP-004", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DT-AT-CKP-004"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-CKP-004"), "");
    BOOST_CHECK(!eng.Apply("DT-AT-CKP-004", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("DT-AT-CKP-004"));

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-003"));
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "has pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-003"));
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "private pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-003"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-003"), "");

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DT-AT-RLP-003"));
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DT-AT-RLP-003"));

    BOOST_CHECK(eng.Apply("DT-AT-RLP-003", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-003"), "s1");
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "fp4", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-003"), "s1");
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "has pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-003"), "s1");
    BOOST_CHECK(!eng.Apply("DT-AT-RLP-003", "private note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-003"), "s1");
    BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_release_stays_unqualified)
{
    modelnet::Dtat04 eng;
    std::string err = "stale";

    for (const char* id : kIds) {
        if (std::string(id) == "DT-AT-CKP-004") {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text(id), "");
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text(id), "");
            BOOST_CHECK(!eng.qualified());
            continue;
        }
        if (std::string(id) == "DT-AT-RLP-006") {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), false, err));
            BOOST_CHECK_EQUAL(err, "ROUTE");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text(id), "");
        }
        BOOST_CHECK(eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(id), "s1");
        BOOST_CHECK_EQUAL(eng.scenario_status(), "NOT_RUN");
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("DT-AT-RLP-006", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(eng.stored("DT-AT-RLP-006"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-006"), "s1");

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
    BOOST_CHECK(eng.stored("DT-AT-RLP-001"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-RLP-008"), "s1");
    BOOST_CHECK(eng.stored("DT-AT-CKP-008"));
    BOOST_CHECK_EQUAL(eng.text("DT-AT-CKP-001"), "s1");
    BOOST_CHECK(!eng.stored("DT-AT-CKP-004"));
    BOOST_CHECK(!eng.stored("DT-AT-RLP-009"));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Dtat04 eng;
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
