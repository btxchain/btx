// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp49/grp49.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp49& eng)
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
    "DT-RLP-006", "DT-RLP-007", "DT-RLP-008",
    "DT-CKP-001", "DT-CKP-003", "DT-CKP-004", "DT-CKP-005", "DT-CKP-006", "DT-CKP-007", "DT-CKP-008",
    "DT-WAN-001", "DT-WAN-002", "DT-WAN-003", "DT-WAN-004", "DT-WAN-005", "DT-WAN-006", "DT-WAN-008",
    "DT-SEC-001", "DT-SEC-002",
};

const char* const kEngines[] = {
    "deepinfer", "vllm", "sglang", "lmcache", "deepep", "deepgemm",
    "dualpipe", "dualpipev", "nixl", "mooncake", "rdma",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp49_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(each_id_stores_once_and_stays_unqualified)
{
    modelnet::Grp49 eng;
    for (const char* id : kIds) {
        std::string err = "stale";
        if (std::string(id) == "DT-CKP-004") {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK(!eng.qualified());
            BOOST_CHECK(!eng.release_qualified());
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
        } else if (std::string(id) == "DT-WAN-001") {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
            BOOST_CHECK_EQUAL(err, "NO_ROUTE");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(0), true, err));
            BOOST_CHECK_EQUAL(err, "NO_ROUTE");
            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, "NO_ROUTE");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        } else {
            if (std::string(id) == "DT-RLP-006") {
                BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), false, err));
                BOOST_CHECK_EQUAL(err, "ROUTE");
                BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
                BOOST_CHECK_EQUAL(eng.text_of(id), "");
            }
            BOOST_CHECK(eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK(err.empty());
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.text_of(id), "s1");

            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(0), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
            BOOST_CHECK_EQUAL(err, "REPLAY");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.text_of(id), "s1");

            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, "UNCHANGED");
            BOOST_CHECK_EQUAL(eng.text_of(id), "s1");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        }

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
    BOOST_CHECK(!eng.Apply("DT-RLP-006", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-006"), "s1");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(refusals_store_nothing)
{
    modelnet::Grp49 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("DT-CKP-002", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-WAN-007", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-007"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-RLP-007", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-007"), "");

    BOOST_CHECK(!eng.Apply("DT-RLP-007", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-007"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-RLP-008", "s1", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-008"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-RLP-007", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-007"), "");
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-WAN-001", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-001"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-RLP-006", "", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-RLP-006", "s1", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-RLP-006", "s1", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-RLP-006", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-006"), "");

    for (const char* name : kEngines) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("DT-SEC-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(eng.stored("DT-SEC-001"), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-001"), "");
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }
    BOOST_CHECK(!eng.Apply("DT-RLP-006", "vllm", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-CKP-003", "pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-CKP-003"), "");
    BOOST_CHECK(!eng.Apply("DT-CKP-003", "s1pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-RLP-006", "pickle", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-SEC-002", "pickle private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-002"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-SEC-002", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-SEC-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-SEC-002"), "");
    BOOST_CHECK(!eng.Apply("DT-WAN-002", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-WAN-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-RLP-006", "private", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-CKP-004", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-CKP-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());

    BOOST_CHECK(eng.Apply("DT-RLP-007", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-007"), "s1");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-007"), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Apply("DT-RLP-008", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-008"), "s1");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-008"), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Apply("DT-RLP-007", "pickle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-007"), "s1");
    BOOST_CHECK(!eng.Apply("DT-RLP-007", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-007"), "s1");
    BOOST_CHECK(!eng.Apply("DT-RLP-007", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-007"), "s1");
    BOOST_CHECK(!eng.Apply("DT-RLP-007", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DT-RLP-007"), "s1");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-007"), static_cast<int64_t>(1));

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
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
