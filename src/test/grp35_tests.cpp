// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp35/grp35.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp35& eng)
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
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
}

const char* kIds[] = {
    "ASR-EVD-003",
    "ASR-EVD-004",
    "ASR-EVD-005",
    "ASR-CAP-001",
    "ASR-CAP-002",
    "ASR-CAP-003",
    "ASR-CAP-004",
    "ASR-ART-001",
    "ASR-ART-002",
    "ASR-ART-003",
    "ASR-ART-004",
    "ASR-ART-005",
    "ASR-KVC-001",
    "ASR-KVC-002",
    "ASR-KVC-003",
    "ASR-KVC-004",
    "ASR-KVC-005",
    "ASR-KVC-006",
    "ASR-TRN-001",
    "ASR-TRN-002",
};

const char* kEngines[] = {
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
    "deepinfer",
    "dualpipe",
    "fp8",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp35_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(every_id_stores_replays_and_stays_unqualified)
{
    modelnet::Grp35 eng;
    for (const char* id : kIds) {
        std::string err = "stale";
        BOOST_CHECK(eng.Apply(id, "noted", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text(id), "noted");
        BOOST_CHECK(!eng.Apply(id, "noted", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(id), "noted");
        BOOST_CHECK(!eng.Apply(id, "other", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(id), "noted");
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        BOOST_CHECK(!eng.Release(err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.release_qualified());
        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK(!eng.hardware_qualified());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_text_stores_nothing)
{
    modelnet::Grp35 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-EVD-003", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("ASR-EVD-003"));
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-003"), "");
    BOOST_CHECK(!eng.Apply("ASR-EVD-003", "a private note", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("ASR-EVD-003"));
    BOOST_CHECK(eng.Apply("ASR-EVD-003", "noted", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-003"), "noted");
    BOOST_CHECK(!eng.Apply("ASR-EVD-003", "still private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-003"), "noted");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engine_names_are_absent)
{
    modelnet::Grp35 eng;
    std::string err = "stale";
    for (const char* name : kEngines) {
        BOOST_CHECK(!eng.Apply("ASR-EVD-004", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("ASR-EVD-004"));
        BOOST_CHECK_EQUAL(eng.text("ASR-EVD-004"), "");
    }
    BOOST_CHECK(modelnet::NifDtEngineLinked("fp8"));
    BOOST_CHECK(!eng.Apply("ASR-EVD-004", "fp8", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.stored("ASR-EVD-004"));
    BOOST_CHECK(eng.Apply("ASR-EVD-004", "noted", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-004"), "noted");
    BOOST_CHECK(!eng.Apply("ASR-EVD-004", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-004"), "noted");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(aux_below_zero_is_bound)
{
    modelnet::Grp35 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-EVD-005", "noted", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("ASR-EVD-005"));
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-005"), "");
    BOOST_CHECK(!eng.Apply("ASR-EVD-005", "noted", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("ASR-EVD-005"));
    BOOST_CHECK(eng.Apply("ASR-EVD-005", "noted", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-005"), "noted");
    BOOST_CHECK(!eng.Apply("ASR-EVD-005", "noted", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text("ASR-EVD-005"), "noted");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_rejects_a_second_host)
{
    modelnet::Grp35 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("ASR-TRN-001", "noted", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.stored("ASR-TRN-001"));
    BOOST_CHECK_EQUAL(eng.text("ASR-TRN-001"), "noted");
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(id_field_cap_and_absent_store_nothing)
{
    modelnet::Grp35 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "noted", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK(!eng.Apply("", "noted", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("ASR-EVD-001", "noted", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("ASR-EVD-001"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("ASR-CAP-001"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "noted", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("ASR-CAP-001"));
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "noted", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("ASR-CAP-001"));
    BOOST_CHECK(eng.Apply("ASR-CAP-001", "noted", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("ASR-CAP-001"), "noted");
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "noted", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.text("ASR-CAP-001"), "noted");
    BOOST_CHECK(!eng.Apply("ASR-CAP-001", "noted", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.text("ASR-CAP-001"), "noted");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
