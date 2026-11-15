// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp47/grp47.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp47& eng)
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
    "DT-NAT-006", "DT-NAT-007", "DT-NAT-008",
    "DT-GRD-001", "DT-GRD-002", "DT-GRD-003", "DT-GRD-004", "DT-GRD-005", "DT-GRD-006", "DT-GRD-007",
    "DT-PAR-001", "DT-PAR-002", "DT-PAR-003", "DT-PAR-004", "DT-PAR-005", "DT-PAR-006", "DT-PAR-007", "DT-PAR-008",
    "DT-OPT-001",
};

const char* const kEngines[] = {
    "deepinfer", "vllm", "sglang", "lmcache", "deepep", "deepgemm",
    "dualpipe", "dualpipev", "nixl", "mooncake", "rdma", "fp8",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp47_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(each_id_stores_once_and_stays_unqualified)
{
    modelnet::Grp47 eng;
    for (const char* id : kIds) {
        std::string err = "stale";
        if (std::string(id) == "DT-PAR-006") {
            BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
            BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK(!eng.gpu());
            BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        } else if (std::string(id) == "DT-NAT-006") {
            BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK(!eng.hardware_qualified());
            BOOST_CHECK(!eng.qualified());
            BOOST_CHECK(!eng.release_qualified());
            BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.hardware_qualified());
        } else {
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
    BOOST_CHECK(!eng.Apply("DT-GRD-003", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-003"), "row");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-003"), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_engine_bound_and_second_host)
{
    modelnet::Grp47 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-NAT-000", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-000"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("DT-NAT-000"), "COMPONENT");

    BOOST_CHECK(!eng.Apply("DT-NAT-007", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-007"), "");

    BOOST_CHECK(!eng.Apply("DT-NAT-007", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-007"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-GRD-001", "row", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-001"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-NAT-007", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-007"), "");

    for (const char* name : kEngines) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name) || std::string(name) == "fp8");
        BOOST_CHECK(!eng.Apply("DT-GRD-002", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(eng.stored("DT-GRD-002"), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.text_of("DT-GRD-002"), "");
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(!eng.Apply("DT-PAR-006", "dualpipe", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-PAR-006", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-PAR-006", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(eng.stored("DT-PAR-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-006"), "");

    BOOST_CHECK(!eng.Apply("DT-OPT-001", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-NAT-006", "keep private out", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-NAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.text_of("DT-NAT-006"), "");

    BOOST_CHECK(eng.Apply("DT-PAR-001", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-001"), "row");
    BOOST_CHECK(eng.Apply("DT-PAR-002", "row", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-002"), "row");

    BOOST_CHECK(!eng.Apply("DT-PAR-001", "private note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-001"), "row");
    BOOST_CHECK(!eng.Apply("DT-PAR-001", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text_of("DT-PAR-001"), "row");
    BOOST_CHECK(!eng.Apply("DT-GRD-003", "other", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-GRD-003"), static_cast<int64_t>(0));

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
    BOOST_CHECK(!eng.hardware_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
