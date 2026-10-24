// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp50/grp50.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp50& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
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
}

struct KnownRow {
    const char* id;
    const char* text;
    bool simulation;
    bool spend_only;
};

const KnownRow kKnown[] = {
    {"DT-SEC-003", "purpose-policy", false, false},
    {"DT-SEC-004", "liability-bound", false, false},
    {"DT-SEC-005", "accepted-tokens", false, false},
    {"DT-SEC-006", "worker-isolation", false, false},
    {"DT-SEC-007", "isolated-candidate", false, false},
    {"DT-SEC-008", "deadline-kept", false, false},
    {"DT-SIM-001", "modeled-assumptions", true, false},
    {"DT-SIM-002", "dependency-order", true, false},
    {"DT-SIM-003", "schedule-compare", true, false},
    {"DT-SIM-004", "sensitivity-sweep", true, false},
    {"DT-SIM-005", "held-out-trace", true, false},
    {"DT-SIM-007", "quality-and-cost", true, false},
    {"DT-SIM-008", "failure-cycle", true, false},
    {"DT-REL-001", "obligations-binding", false, false},
    {"DT-REL-002", "local-paths", false, false},
    {"DT-REL-004", "named-absent", false, false},
    {"DT-REL-005", "doc-surface", false, false},
    {"DT-REL-006", "provenance-record", false, false},
    {"DT-REL-008", "owner-authorization", false, true},
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp50_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Grp50 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("DT-NO-SUCH", "purpose-policy", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-NO-SUCH"));

    BOOST_CHECK(!eng.Apply("DT-REL-003", "offline-image", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-REL-003"));

    BOOST_CHECK(!eng.Apply("DT-REL-007", "broader-gate", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-REL-007"));

    BOOST_CHECK(!eng.Apply("DT-SIM-006", "agree", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DT-SIM-006"));

    BOOST_CHECK(!eng.Apply("DT-SEC-003", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DT-SEC-003"));

    BOOST_CHECK(!eng.Apply("DT-SEC-003", "purpose-policy", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DT-SEC-003"));

    BOOST_CHECK(!eng.Apply("DT-SEC-003", "purpose-policy", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DT-SEC-003"));

    BOOST_CHECK(!eng.Apply("DT-SEC-003", "purpose-policy", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DT-SEC-003"));

    BOOST_CHECK(eng.Apply("DT-SEC-003", "purpose-policy", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DT-SEC-003"));
    BOOST_CHECK_EQUAL(eng.text("DT-SEC-003"), "purpose-policy");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_fp8_dualpipe_private_and_rel)
{
    modelnet::Grp50 eng;
    std::string err = "stale";
    const char* const remote[] = {
        "deepinfer",
        "vllm",
        "sglang",
        "lmcache",
        "deepep",
        "deepgemm",
        "dualpipe",
        "dualpipev",
        "nixl",
        "mooncake",
        "rdma",
    };

    BOOST_CHECK(modelnet::NifDtEngineLinked("fp8"));
    BOOST_CHECK(!eng.Apply("DT-SEC-004", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.stored("DT-SEC-004"));
    BOOST_CHECK(!eng.gpu());

    BOOST_CHECK(!modelnet::NifDtEngineLinked("dualpipe"));
    BOOST_CHECK(!eng.Apply("DT-SEC-004", "dualpipe", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("DT-SEC-004"));

    for (const char* name : remote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("DT-SEC-004", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK(!eng.stored("DT-SEC-004"));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("DT-SEC-004", "private trajectory", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DT-SEC-004"));

    BOOST_CHECK(!eng.Apply("DT-REL-004", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("DT-REL-004"));
    BOOST_CHECK(!eng.broadcast());

    BOOST_CHECK(!eng.Apply("DT-REL-008", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("DT-REL-008", "owner-authorization", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("DT-REL-008", "owner-authorization", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("DT-REL-008", "owner-authorization", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.stored("DT-REL-008"));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Apply("DT-REL-008", "owner-authorization", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.stored("DT-REL-008"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_release_stays_unqualified)
{
    modelnet::Grp50 eng;
    std::string err = "stale";

    for (const KnownRow& row : kKnown) {
        if (std::string(row.id) == "DT-REL-004") {
            BOOST_CHECK(!eng.Apply(row.id, "rdma", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
            BOOST_CHECK(!eng.stored(row.id));
        }
        if (row.spend_only) {
            BOOST_CHECK(!eng.Apply(row.id, row.text, static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
            BOOST_CHECK(!eng.stored(row.id));
            BOOST_CHECK(!eng.broadcast());
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            continue;
        }
        BOOST_CHECK(eng.Apply(row.id, row.text, static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(row.id));
        BOOST_CHECK_EQUAL(eng.text(row.id), row.text);
        if (row.simulation) {
            BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
        }
        BOOST_CHECK(!eng.Apply(row.id, row.text, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(row.id), row.text);
        BOOST_CHECK(!eng.Apply(row.id, "other-sentence", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(row.id), row.text);
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
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.stored("DT-SIM-001"));
    BOOST_CHECK_EQUAL(eng.text("DT-SIM-008"), "failure-cycle");
    BOOST_CHECK(eng.stored("DT-REL-004"));
    BOOST_CHECK_EQUAL(eng.text("DT-REL-004"), "named-absent");
    BOOST_CHECK(!eng.stored("DT-REL-008"));
    BOOST_CHECK(!eng.stored("DT-REL-003"));
    BOOST_CHECK(!eng.stored("DT-REL-007"));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Grp50 eng;
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
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
