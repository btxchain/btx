// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp37/grp37.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

const char* kIds[] = {
    "ASR-SEC-001",
    "ASR-SEC-002",
    "ASR-REC-001",
    "ASR-REC-002",
    "ASR-OBS-001",
    "ASR-MIG-001",
    "ASR-MIG-002",
    "ASR-ACC-001",
    "ASR-ACC-002",
    "ASR-PUB-001",
    "ASR-PUB-002",
    "ASR-PUB-003",
    "ASR-PUB-004",
    "DS-NAT-001",
    "DS-NAT-002",
    "DS-NAT-003",
    "DS-NAT-004",
    "DS-NAT-005",
    "DS-NAT-006",
    "DS-HIRE-001",
};

const char* kRemote[] = {
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

void Idle(modelnet::Grp37& eng)
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
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp37_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_or_empty_id)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK_EQUAL(eng.aux_of(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("NO-SUCH", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("NO-SUCH"));
    BOOST_CHECK(!eng.Apply("ASR-SEC-003", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(empty_text_is_field)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-SEC-001", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("ASR-SEC-001"));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-001"), "");
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-HIRE-001"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(aux_bounds)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-SEC-001", "row", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("ASR-SEC-001"));
    BOOST_CHECK(!eng.Apply("ASR-SEC-002", "row", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("ASR-SEC-002"));
    BOOST_CHECK(eng.Apply("ASR-REC-001", "low", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-REC-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-REC-001"), "low");
    BOOST_CHECK(eng.Apply("ASR-REC-002", "high", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-REC-002"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-REC-002"), "high");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(flag_false_is_absent)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-OBS-001", "vllm", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("ASR-OBS-001"));
    BOOST_CHECK(!eng.Apply("ASR-OBS-001", "private note", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("ASR-OBS-001"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_engine_names)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    for (const char* name : kRemote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("ASR-PUB-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("ASR-PUB-001"));
        BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-001"), "");
        BOOST_CHECK_EQUAL(eng.aux_of("ASR-PUB-001"), static_cast<int64_t>(0));
    }
    BOOST_CHECK(modelnet::NifDtEngineLinked("memory"));
    BOOST_CHECK(eng.Apply("ASR-PUB-001", "memory", static_cast<int64_t>(2), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("ASR-PUB-001"));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-001"), "memory");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-PUB-001"), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.Apply("ASR-PUB-001", "rdma", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PUB-001"), "memory");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-PUB-001"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_text)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-SEC-002", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("ASR-SEC-002"));
    BOOST_CHECK(!eng.Apply("ASR-SEC-002", "keep private body", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("ASR-SEC-002"));
    BOOST_CHECK(eng.Apply("ASR-SEC-002", "public row", static_cast<int64_t>(5), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-002"), "public row");
    BOOST_CHECK(!eng.Apply("ASR-SEC-002", "still private", static_cast<int64_t>(5), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-SEC-002"), "public row");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-SEC-002"), static_cast<int64_t>(5));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(each_known_id_stores_once)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    for (const char* id : kIds) {
        const std::string text = std::string("row ") + id;
        BOOST_CHECK(eng.Apply(id, text, static_cast<int64_t>(7), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), text);
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(7));
        BOOST_CHECK(!eng.Apply(id, text, static_cast<int64_t>(7), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text_of(id), text);
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(7));
        BOOST_CHECK(!eng.Apply(id, text + " other", static_cast<int64_t>(7), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text_of(id), text);
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(7));
    }
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(eng.stored("DS-HIRE-001"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "row DS-HIRE-001");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(upgrade_refusal_keeps_first_aux)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("ASR-MIG-001", "first", static_cast<int64_t>(10), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-MIG-001"), static_cast<int64_t>(10));
    BOOST_CHECK(!eng.Apply("ASR-MIG-001", "raised", static_cast<int64_t>(11), true, err));
    BOOST_CHECK_EQUAL(err, "UPGRADE");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-001"), "first");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-MIG-001"), static_cast<int64_t>(10));
    BOOST_CHECK(!eng.Apply("ASR-MIG-001", "first", static_cast<int64_t>(90), true, err));
    BOOST_CHECK_EQUAL(err, "UPGRADE");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-MIG-001"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-001"), "first");
    BOOST_CHECK(!eng.Apply("ASR-MIG-001", "first", static_cast<int64_t>(10), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-MIG-001"), static_cast<int64_t>(10));
    BOOST_CHECK(!eng.Apply("ASR-MIG-001", "lower", static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-001"), "first");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-MIG-001"), static_cast<int64_t>(10));
    BOOST_CHECK(eng.Apply("ASR-MIG-002", "mig", static_cast<int64_t>(3), true, err));
    BOOST_CHECK(!eng.Apply("ASR-MIG-002", "mig", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-MIG-002"), "mig");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-MIG-002"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(windows_and_gpu_are_not_passed)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-ACC-002", "gpu", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("ASR-ACC-002"));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Apply("ASR-ACC-002", "windows", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("ASR-ACC-002"));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(eng.Apply("ASR-ACC-002", "held", static_cast<int64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-002"), "held");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-ACC-002"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.Apply("ASR-ACC-002", "gpu", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-002"), "held");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-ACC-002"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.Apply("ASR-ACC-002", "windows", static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-002"), "held");
    BOOST_CHECK_EQUAL(eng.aux_of("ASR-ACC-002"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(eng.Apply("ASR-ACC-001", "gpu", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("ASR-ACC-001"), "gpu");
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_reject_a_second_host)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("DS-NAT-001", "one", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-001"), "one");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(refusal_keeps_the_first)
{
    modelnet::Grp37 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("DS-NAT-006", "kept", static_cast<int64_t>(6), true, err));
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "", static_cast<int64_t>(6), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "kept", static_cast<int64_t>(-5), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "kept", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "kept", static_cast<int64_t>(6), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-006"), "kept");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-NAT-006"), static_cast<int64_t>(6));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
