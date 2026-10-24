// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/mod01/mod01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Mod01& eng)
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
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
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
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
}

struct KnownRow {
    const char* id;
    bool journey;
    const char* exact;
    const char* exact_err;
    bool qualify_named;
};

const KnownRow kKnown[] = {
    {"git_origin", false, "sha1", "DIGEST", false},
    {"git_attestation", false, "account", "ATTEST", false},
    {"agent_lineage", false, "inherit", "GRANT", false},
    {"agent_guard", false, "inprocess", "PROCESS", false},
    {"incident", false, "blocklist", "SCOPE", false},
    {"realm_promotion", false, "one", "QUORUM", false},
    {"fleet_rollout", false, "complete", "STATE", false},
    {"git_remote", false, "shell", "HELPER", false},
    {"slice_source", true, nullptr, nullptr, false},
    {"slice_views", true, nullptr, nullptr, false},
    {"slice_replay", true, nullptr, nullptr, false},
    {"slice_admit", true, nullptr, nullptr, false},
    {"slice_guard", true, nullptr, nullptr, false},
    {"slice_wan", true, nullptr, nullptr, false},
    {"slice_qualify", true, nullptr, nullptr, true},
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mod01_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(id_text_aux_and_flag)
{
    modelnet::Mod01 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK(eng.text("").empty());
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(!eng.Apply("no-such", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("no-such"));

    BOOST_CHECK(!eng.Apply("GIT_ORIGIN", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("GIT_ORIGIN"));

    BOOST_CHECK(!eng.Apply("git_origin", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("git_origin"));

    BOOST_CHECK(!eng.Apply("git_origin", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("git_origin"));

    BOOST_CHECK(!eng.Apply("git_origin", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("git_origin"));

    BOOST_CHECK(!eng.Apply("git_origin", "s1", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("git_origin"));

    BOOST_CHECK(!eng.Apply("git_origin", "vllm", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("git_origin"));

    BOOST_CHECK(eng.Apply("git_origin", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("git_origin"));
    BOOST_CHECK_EQUAL(eng.text("git_origin"), "s1");
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(eng.Apply("git_attestation", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("git_attestation"));
    BOOST_CHECK_EQUAL(eng.text("git_attestation"), "s1");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.passed());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engines_private_slices_and_exact)
{
    modelnet::Mod01 eng;
    std::string err = "stale";
    const char* const exact_engines[] = {
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
    for (const char* name : exact_engines) {
        BOOST_CHECK(!eng.Apply("git_origin", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("git_origin"));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.gpu_passed());
        BOOST_CHECK(!eng.passed());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!modelnet::NifDtEngineLinked("dualpipe"));
    BOOST_CHECK(!eng.Apply("git_origin", "dualpipe", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("git_origin"));

    BOOST_CHECK(!modelnet::NifDtEngineLinked("deepep"));
    BOOST_CHECK(eng.Apply("incident", "deepep", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("incident"));
    BOOST_CHECK_EQUAL(eng.text("incident"), "deepep");
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!modelnet::NifDtEngineLinked("dualpipev"));
    BOOST_CHECK(eng.Apply("fleet_rollout", "dualpipev", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("fleet_rollout"), "dualpipev");
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(eng.Apply("agent_lineage", "vllm-extra", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("agent_lineage"), "vllm-extra");

    BOOST_CHECK(!eng.Apply("agent_guard", "private trajectory", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("agent_guard"));
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(!eng.Apply("git_origin", "xprivatey", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("git_origin"));

    BOOST_CHECK(!eng.Apply("slice_qualify", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("slice_qualify"));

    BOOST_CHECK(!eng.Apply("slice_qualify", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("slice_qualify"));

    const char* const qualify_named[] = {"windows", "macos", "gpu"};
    for (const char* name : qualify_named) {
        BOOST_CHECK(!eng.Apply("slice_qualify", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.stored("slice_qualify"));
        BOOST_CHECK(!eng.windows_passed());
        BOOST_CHECK(!eng.gpu_passed());
        BOOST_CHECK(!eng.passed());
    }

    BOOST_CHECK(!eng.Apply("slice_qualify", "Windows", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "JOURNEY");
    BOOST_CHECK(!eng.stored("slice_qualify"));

    BOOST_CHECK(!eng.Apply("slice_qualify", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "JOURNEY");
    BOOST_CHECK(!eng.stored("slice_qualify"));
    BOOST_CHECK(eng.text("slice_qualify").empty());

    const char* const journey[] = {
        "slice_source",
        "slice_views",
        "slice_replay",
        "slice_admit",
        "slice_guard",
        "slice_wan",
    };
    for (const char* id : journey) {
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "JOURNEY");
        BOOST_CHECK(!eng.stored(id));
        BOOST_CHECK(eng.text(id).empty());
        BOOST_CHECK(!eng.passed());
        BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "JOURNEY");
        BOOST_CHECK(!eng.stored(id));
    }

    BOOST_CHECK(!eng.Apply("slice_source", "windows", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "JOURNEY");
    BOOST_CHECK(!eng.stored("slice_source"));

    BOOST_CHECK(!eng.Apply("slice_source", "sha1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "JOURNEY");
    BOOST_CHECK(!eng.stored("slice_source"));

    BOOST_CHECK(!eng.Apply("slice_source", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("slice_source"));

    BOOST_CHECK(!eng.Apply("git_origin", "sha1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK(!eng.stored("git_origin"));
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(eng.Apply("git_origin", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("git_origin"), "s1");
    BOOST_CHECK(!eng.Apply("git_origin", "sha1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(eng.text("git_origin"), "s1");
    BOOST_CHECK(!eng.Apply("git_origin", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(eng.text("git_origin"), "s1");

    BOOST_CHECK(!eng.Apply("git_attestation", "account", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ATTEST");
    BOOST_CHECK(!eng.stored("git_attestation"));

    BOOST_CHECK(!eng.Apply("agent_lineage", "inherit", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "GRANT");
    BOOST_CHECK(eng.stored("agent_lineage"));
    BOOST_CHECK_EQUAL(eng.text("agent_lineage"), "vllm-extra");

    BOOST_CHECK(!eng.Apply("agent_guard", "inprocess", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PROCESS");
    BOOST_CHECK(!eng.stored("agent_guard"));
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(!eng.Apply("realm_promotion", "one", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK(!eng.stored("realm_promotion"));

    BOOST_CHECK(!eng.Apply("fleet_rollout", "complete", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(eng.stored("fleet_rollout"));
    BOOST_CHECK_EQUAL(eng.text("fleet_rollout"), "dualpipev");

    BOOST_CHECK(!eng.Apply("git_remote", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("git_remote"));
    BOOST_CHECK(!eng.Apply("git_remote", "shell", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "HELPER");
    BOOST_CHECK(!eng.stored("git_remote"));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.passed());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_release_stays_unqualified)
{
    modelnet::Mod01 eng;
    std::string err = "stale";

    for (const KnownRow& row : kKnown) {
        if (row.qualify_named) {
            const char* const qualify_named[] = {"windows", "macos", "gpu"};
            for (const char* name : qualify_named) {
                BOOST_CHECK(!eng.Apply(row.id, name, static_cast<int64_t>(1), true, err));
                BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
                BOOST_CHECK(!eng.stored(row.id));
                BOOST_CHECK(eng.text(row.id).empty());
                BOOST_CHECK(!eng.passed());
            }
        }
        if (row.exact != nullptr) {
            BOOST_CHECK(!eng.Apply(row.id, row.exact, static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, std::string(row.exact_err));
            BOOST_CHECK(!eng.stored(row.id));
            BOOST_CHECK(eng.text(row.id).empty());
            BOOST_CHECK(!eng.process_present());
            BOOST_CHECK(!eng.passed());
        }
        if (row.journey) {
            BOOST_CHECK(!eng.Apply(row.id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "JOURNEY");
            BOOST_CHECK(!eng.stored(row.id));
            BOOST_CHECK(eng.text(row.id).empty());
            BOOST_CHECK(!eng.passed());
            BOOST_CHECK(!eng.Apply(row.id, "s2", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "JOURNEY");
            BOOST_CHECK(!eng.stored(row.id));
            continue;
        }
        BOOST_CHECK(eng.Apply(row.id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(row.id));
        BOOST_CHECK_EQUAL(eng.text(row.id), "s1");
        BOOST_CHECK(!eng.passed());
        BOOST_CHECK(!eng.process_present());
        BOOST_CHECK(!eng.Apply(row.id, "s1", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(row.id), "s1");
        BOOST_CHECK(!eng.Apply(row.id, "s2", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(row.id), "s1");
        if (row.exact != nullptr) {
            BOOST_CHECK(!eng.Apply(row.id, row.exact, static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, std::string(row.exact_err));
            BOOST_CHECK_EQUAL(eng.text(row.id), "s1");
            BOOST_CHECK(!eng.passed());
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
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.stored("git_origin"));
    BOOST_CHECK_EQUAL(eng.text("git_origin"), "s1");
    BOOST_CHECK(eng.stored("agent_guard"));
    BOOST_CHECK_EQUAL(eng.text("agent_guard"), "s1");
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK(!eng.stored("slice_source"));
    BOOST_CHECK(!eng.stored("slice_views"));
    BOOST_CHECK(!eng.stored("slice_replay"));
    BOOST_CHECK(!eng.stored("slice_admit"));
    BOOST_CHECK(!eng.stored("slice_guard"));
    BOOST_CHECK(!eng.stored("slice_wan"));
    BOOST_CHECK(!eng.stored("slice_qualify"));
    BOOST_CHECK(!eng.stored("no-such"));
    BOOST_CHECK(!eng.passed());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::Mod01 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.process_present());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
