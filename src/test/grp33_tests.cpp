// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp33/grp33.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

const char* const kIds[] = {
    "ASR-NAT-001",
    "ASR-NAT-002",
    "ASR-NAT-003",
    "ASR-NAT-004",
    "ASR-NAT-005",
    "ASR-NAT-006",
    "ASR-GRF-001",
    "ASR-GRF-002",
    "ASR-GRF-003",
    "ASR-GRF-004",
    "ASR-GRF-005",
    "ASR-PLN-001",
    "ASR-PLN-002",
    "ASR-PLN-003",
    "ASR-PLN-004",
    "ASR-PLN-005",
    "ASR-PLN-006",
    "ASR-PLN-007",
    "ASR-EXE-001",
    "ASR-EXE-002",
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
};

void Idle(modelnet::Grp33& eng)
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
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp33_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(known_ids_store_replay_release)
{
    modelnet::Grp33 eng;
    std::string err;
    for (const char* id : kIds) {
        BOOST_CHECK(eng.Apply(id, "note", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.text_of(id), "note");
        BOOST_CHECK_EQUAL(eng.classification(id), "COMPONENT");
        BOOST_CHECK(!eng.Apply(id, "note", static_cast<int64_t>(2), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.text_of(id), "note");
        BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        BOOST_CHECK(!eng.Release(err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.release_qualified());
        BOOST_CHECK_EQUAL(eng.text_of(id), "note");
        BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(unchanged_keeps_first)
{
    modelnet::Grp33 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("ASR-NAT-001", "note", static_cast<int64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Apply("ASR-NAT-001", "other", static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-001"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-001"), "note");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_engine_bound_and_hosts)
{
    modelnet::Grp33 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-NAT-002", "keep private out", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-002"), "");
    BOOST_CHECK(!eng.Apply("ASR-NAT-002", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-002"), "");
    for (const char* engine : kEngines) {
        BOOST_CHECK(!eng.Apply("ASR-NAT-003", engine, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-003"), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-003"), "");
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }
    BOOST_CHECK(!eng.Apply("ASR-NAT-004", "note", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-NAT-004"), "");
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(field_cap_absent_and_id)
{
    modelnet::Grp33 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("NO-SUCH", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.classification("NO-SUCH"), "");
    BOOST_CHECK_EQUAL(eng.classification("P2P-1"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK(!eng.Apply("P2P-1", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.text_of("P2P-1"), "");
    BOOST_CHECK(!eng.Apply("ASR-PLN-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "");
    BOOST_CHECK(!eng.Apply("ASR-PLN-001", "over", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-PLN-001", "note", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "");
    BOOST_CHECK(eng.Apply("ASR-PLN-001", "zero", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-001"), "zero");
    BOOST_CHECK(eng.Apply("ASR-PLN-002", "cap", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PLN-002"), "cap");
    BOOST_CHECK(!eng.Apply("ASR-PLN-002", "cap", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.stored("ASR-PLN-002"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
