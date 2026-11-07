// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp46/grp46.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp46& eng)
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
    "NIF-QA-004", "NIF-QA-005", "NIF-QA-006",
    "NIF-GOV-001", "NIF-GOV-002", "NIF-GOV-003", "NIF-GOV-004",
    "DT-EVD-001", "DT-EVD-002", "DT-EVD-003", "DT-EVD-004",
    "DT-EVD-005", "DT-EVD-006", "DT-EVD-007", "DT-EVD-008",
    "DT-NAT-001", "DT-NAT-002", "DT-NAT-003", "DT-NAT-005",
};

const char* const kEngines[] = {
    "vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma", "deepinfer",
    "dualpipe", "dualpipev", "deepep", "deepgemm", "fp8",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp46_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(each_id_stores_once)
{
    modelnet::Grp46 eng;
    for (const char* id : kIds) {
        std::string err = "stale";
        if (std::string(id) == "NIF-GOV-004") {
            BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
            BOOST_CHECK_EQUAL(err, "0");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "0");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.qualified());
            BOOST_CHECK(!eng.release_qualified());
            continue;
        }

        const int64_t aux = static_cast<int64_t>(1);
        BOOST_CHECK(eng.Apply(id, "row", aux, true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.text_of(id), "row");
        BOOST_CHECK_EQUAL(eng.classification(id), "COMPONENT");
        BOOST_CHECK(!eng.hardware_qualified());

        BOOST_CHECK(!eng.Apply(id, "row", aux, true, err));
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
    std::string err;
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-006"), "COMPONENT");
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-006"), "row");
    BOOST_CHECK(!eng.hardware_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(gov_spend_and_nat_expiry)
{
    modelnet::Grp46 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("NIF-GOV-004", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-004"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("NIF-GOV-004", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-004"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("NIF-GOV-004", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-004"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("NIF-GOV-004", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-004"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("NIF-GOV-004", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-004"), "");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-NAT-003", "row", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-003"), "");

    BOOST_CHECK(!eng.Apply("DT-NAT-003", "row", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-003"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-NAT-003", "private", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-003"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-NAT-003", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-003"), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Apply("DT-NAT-003", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-003"), "row");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-003"), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Apply("DT-NAT-003", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-003"), "row");

    BOOST_CHECK(!eng.Apply("DT-NAT-003", "later", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-003"), "row");
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-003"), "COMPONENT");
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(evidence_stays_component)
{
    modelnet::Grp46 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("DT-EVD-006", "hardware", static_cast<int64_t>(40), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-006"), "hardware");
    BOOST_CHECK_EQUAL(eng.classification("DT-EVD-006"), "COMPONENT");
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-006"), "hardware");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(refusals_and_one_host)
{
    modelnet::Grp46 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-QA-001", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("NIF-QA-001"), "COMPONENT");

    BOOST_CHECK(!eng.Apply("NIF-QA-004", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-004"), "");

    BOOST_CHECK(!eng.Apply("NIF-QA-004", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-QA-005", "row", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-005"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("NIF-QA-006", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("NIF-QA-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-006"), "");

    for (const char* name : kEngines) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name) || std::string(name) == "fp8");
        BOOST_CHECK(!eng.Apply("NIF-GOV-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(eng.stored("NIF-GOV-001"), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.text_of("NIF-GOV-001"), "");
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("DT-EVD-001", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-EVD-002", "keep private out", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-EVD-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-002"), "");

    BOOST_CHECK(eng.Apply("DT-EVD-003", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-003"), "row");
    BOOST_CHECK(eng.Apply("DT-EVD-004", "row", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-004"), "row");

    BOOST_CHECK(!eng.Apply("DT-EVD-003", "private note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-003"), "row");
    BOOST_CHECK(!eng.Apply("DT-EVD-003", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text_of("DT-EVD-003"), "row");

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
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
