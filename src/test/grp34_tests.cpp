// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp34/grp34.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp34& eng)
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
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

const char* const kIds[] = {
    "ASR-EXE-003", "ASR-EXE-004", "ASR-EXE-005", "ASR-EXE-006", "ASR-EXE-007",
    "ASR-NET-001", "ASR-NET-002", "ASR-NET-003", "ASR-NET-004", "ASR-NET-005",
    "ASR-HND-001", "ASR-HND-002", "ASR-HND-003", "ASR-HND-004",
    "ASR-PRG-001", "ASR-PRG-002", "ASR-PRG-003", "ASR-PRG-004",
    "ASR-EVD-001", "ASR-EVD-002",
};

const char* const kEngines[] = {
    "vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma", "deepinfer", "dualpipe", "fp8",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp34_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(each_id_stores_once_and_stays_unqualified)
{
    modelnet::Grp34 eng;
    for (const char* id : kIds) {
        std::string err = "stale";
        BOOST_CHECK(eng.Apply(id, "row", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.text_of(id), "row");
        BOOST_CHECK_EQUAL(eng.classification(id), "COMPONENT");

        BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(0), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.text_of(id), "row");

        BOOST_CHECK(!eng.Apply(id, "other", static_cast<int64_t>(100), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text_of(id), "row");
        BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));

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
    std::string err = "stale";
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_engine_bound_and_second_host)
{
    modelnet::Grp34 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-EXE-000", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-000"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("ASR-EXE-000"), "COMPONENT");

    BOOST_CHECK(!eng.Apply("ASR-EXE-003", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-003"), "");

    BOOST_CHECK(!eng.Apply("ASR-EXE-003", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-NET-001", "row", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("ASR-NET-001"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("ASR-EXE-003", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EXE-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EXE-003"), "");

    for (const char* name : kEngines) {
        BOOST_CHECK(!eng.Apply("ASR-HND-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(eng.stored("ASR-HND-001"), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.text_of("ASR-HND-001"), "");
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("ASR-EVD-001", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("ASR-EVD-002", "keep private out", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("ASR-EVD-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("ASR-EVD-002"), "");

    BOOST_CHECK(eng.Apply("ASR-PRG-001", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRG-001"), "row");
    BOOST_CHECK(eng.Apply("ASR-PRG-002", "row", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRG-002"), "row");

    BOOST_CHECK(!eng.Apply("ASR-PRG-001", "private note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRG-001"), "row");
    BOOST_CHECK(!eng.Apply("ASR-PRG-001", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text_of("ASR-PRG-001"), "row");

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
