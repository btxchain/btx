// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp44/grp44.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp44& eng)
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
    "NIF-PROF-005",
    "NIF-EXEC-002", "NIF-EXEC-003", "NIF-EXEC-004", "NIF-EXEC-006",
    "NIF-KV-001", "NIF-KV-002", "NIF-KV-003", "NIF-KV-004",
    "NIF-KV-005", "NIF-KV-006", "NIF-KV-007", "NIF-KV-008",
    "NIF-LAN-001", "NIF-LAN-002", "NIF-LAN-006", "NIF-LAN-007", "NIF-LAN-008",
    "NIF-ISL-001", "NIF-ISL-002",
};

const char* const kRemote[] = {
    "deepinfer", "vllm", "sglang", "lmcache", "deepep", "deepgemm",
    "dualpipe", "dualpipev", "nixl", "mooncake", "rdma",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp44_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(each_id_keeps_the_first_text)
{
    modelnet::Grp44 eng;
    for (const char* id : kIds) {
        const std::string key(id);
        std::string err = "stale";
        BOOST_CHECK_EQUAL(eng.classification(key), "COMPONENT");
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

        if (key == "NIF-KV-004" || key == "NIF-KV-007") {
            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
            BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(key), "");
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.gpu());
            BOOST_CHECK(!eng.launched());
        } else if (key == "NIF-LAN-002") {
            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "HINT");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(key), "");
            BOOST_CHECK(!eng.Apply(key, "other", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "HINT");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(key), "");
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        } else if (key == "NIF-LAN-001") {
            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(0), true, err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(2), true, err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));

            BOOST_CHECK(eng.Apply(key, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK(err.empty());
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.text_of(key), "row");

            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
            BOOST_CHECK_EQUAL(err, "REPLAY");
            BOOST_CHECK_EQUAL(eng.text_of(key), "row");

            BOOST_CHECK(!eng.Apply(key, "other", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "UNCHANGED");
            BOOST_CHECK_EQUAL(eng.text_of(key), "row");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(1));

            BOOST_CHECK(!eng.Apply(key, "other", static_cast<int64_t>(2), true, err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK_EQUAL(eng.text_of(key), "row");
            BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        } else {
            BOOST_CHECK(eng.Apply(key, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK(err.empty());
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.text_of(key), "row");
            BOOST_CHECK_EQUAL(eng.classification(key), "COMPONENT");

            BOOST_CHECK(!eng.Apply(key, "row", static_cast<int64_t>(0), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
            BOOST_CHECK_EQUAL(err, "REPLAY");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.text_of(key), "row");

            BOOST_CHECK(!eng.Apply(key, "other", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, "UNCHANGED");
            BOOST_CHECK_EQUAL(eng.text_of(key), "row");
            BOOST_CHECK_EQUAL(eng.stored(key), static_cast<int64_t>(1));
        }

        BOOST_CHECK(!eng.Release(err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.release_qualified());
        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK(!eng.hardware_qualified());
        BOOST_CHECK(!eng.launched());
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.broadcast());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    }
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-005"), "row");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-LAN-001"), "row");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(field_remote_private_and_bounds)
{
    modelnet::Grp44 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-KV-000", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-000"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("NIF-KV-000"), "COMPONENT");

    BOOST_CHECK(!eng.Apply("NIF-PROF-005", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-005"), "");

    BOOST_CHECK(!eng.Apply("NIF-EXEC-002", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-EXEC-003", "row", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-003"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("NIF-EXEC-004", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-004"), "");

    BOOST_CHECK(!eng.Apply("NIF-KV-004", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-KV-004", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-LAN-001", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-LAN-001", "row", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NIF-LAN-002", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-LAN-002"), static_cast<int64_t>(0));

    for (const char* name : kRemote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("NIF-EXEC-006", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(eng.stored("NIF-EXEC-006"), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.text_of("NIF-EXEC-006"), "");
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    }

    BOOST_CHECK(!eng.Apply("NIF-KV-001", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-KV-002", "keep private out", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("NIF-KV-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-KV-002"), "");

    BOOST_CHECK(eng.Apply("NIF-ISL-001", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-001"), "row");
    BOOST_CHECK(eng.Apply("NIF-ISL-002", "row", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-002"), "row");

    BOOST_CHECK(!eng.Apply("NIF-ISL-001", "private note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-001"), "row");
    BOOST_CHECK(!eng.Apply("NIF-ISL-001", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-001"), "row");
    BOOST_CHECK(!eng.Apply("NIF-ISL-001", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-001"), "row");

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-001"), "row");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
