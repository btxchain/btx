// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp45/grp45.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp45& eng)
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
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
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
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
}

int64_t AuxFor(const char* id)
{
    if (std::string(id) == "NIF-ISL-003") return static_cast<int64_t>(0);
    if (std::string(id) == "NIF-ISL-004") return static_cast<int64_t>(100);
    return static_cast<int64_t>(40);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp45_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_or_unknown_id)
{
    modelnet::Grp45 eng;
    std::string err = "stale";
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK(eng.text_of("").empty());
    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("NIF-ISL-001", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("NIF-ISL-001"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-004", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("NIF-QA-004", "note", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("deepinfer", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("deepinfer"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(field_bound_cap_and_flag)
{
    modelnet::Grp45 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("NIF-ISL-003"));
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "note", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("NIF-ISL-003"));
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "note", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "note", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "note", static_cast<int64_t>(1000), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("NIF-ISL-003"));
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "note", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "note", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NIF-ISL-003", "note", static_cast<int64_t>(100), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("NIF-ISL-003"));
    BOOST_CHECK_EQUAL(eng.aux_of("NIF-ISL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_names_and_private_text)
{
    modelnet::Grp45 eng;
    std::string err = "stale";
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
    for (const char* name : kRemote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("NIF-DATA-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("NIF-DATA-001"));
        BOOST_CHECK(eng.text_of("NIF-DATA-001").empty());
    }
    BOOST_CHECK(!eng.Apply("NIF-DATA-005", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("NIF-DATA-005"));
    BOOST_CHECK(!eng.Apply("NIF-DATA-005", "a private row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.Apply("NIF-DATA-005", "not-private", static_cast<int64_t>(40), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("NIF-DATA-005"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(modelnet::NifDtEngineLinked("local"));
    BOOST_CHECK(eng.Apply("NIF-ISL-005", "local", static_cast<int64_t>(40), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("NIF-ISL-005"));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-005"), "local");
    BOOST_CHECK_EQUAL(eng.aux_of("NIF-ISL-005"), static_cast<int64_t>(40));
    BOOST_CHECK(!eng.Apply("NIF-ISL-005", "rdma", static_cast<int64_t>(40), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-005"), "local");
    BOOST_CHECK(!eng.Apply("NIF-ISL-005", "still private", static_cast<int64_t>(40), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("NIF-ISL-005"), "local");
    BOOST_CHECK_EQUAL(eng.aux_of("NIF-ISL-005"), static_cast<int64_t>(40));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(pkg_and_econ_store_nothing)
{
    modelnet::Grp45 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "image", static_cast<int64_t>(-5), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "image", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "image", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "image", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("NIF-PKG-001"));
    BOOST_CHECK(eng.text_of("NIF-PKG-001").empty());
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "image", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Apply("NIF-PKG-001", "other-image", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("NIF-PKG-001"));
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());

    BOOST_CHECK(!eng.Apply("NIF-ECON-004", "a private body", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("NIF-ECON-004"));
    BOOST_CHECK(!eng.Apply("NIF-ECON-004", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("NIF-ECON-004"));
    BOOST_CHECK(!eng.Apply("NIF-ECON-004", "research-row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.stored("NIF-ECON-004"));
    BOOST_CHECK(eng.text_of("NIF-ECON-004").empty());
    BOOST_CHECK_EQUAL(eng.aux_of("NIF-ECON-004"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-ECON-004", "research-row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Apply("NIF-ECON-004", "other-row", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.stored("NIF-ECON-004"));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id)
{
    modelnet::Grp45 eng;
    std::string err = "stale";
    const char* kIds[] = {
        "NIF-ISL-003",
        "NIF-ISL-004",
        "NIF-ISL-005",
        "NIF-PKG-001",
        "NIF-PKG-002",
        "NIF-PKG-003",
        "NIF-PKG-004",
        "NIF-PKG-005",
        "NIF-DATA-001",
        "NIF-DATA-002",
        "NIF-DATA-003",
        "NIF-DATA-005",
        "NIF-ECON-001",
        "NIF-ECON-002",
        "NIF-ECON-003",
        "NIF-ECON-004",
        "NIF-QA-001",
        "NIF-QA-002",
        "NIF-QA-003",
    };
    for (const char* id : kIds) {
        const std::string text = std::string("note-") + id;
        const std::string other = std::string("other-") + id;
        const int64_t aux = AuxFor(id);
        if (std::string(id) == "NIF-ECON-004") {
            BOOST_CHECK(!eng.Apply(id, text, aux, true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
            BOOST_CHECK_EQUAL(err, "0");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK(eng.text_of(id).empty());
            BOOST_CHECK(!eng.Apply(id, other, aux, true, err));
            BOOST_CHECK_EQUAL(err, "0");
            BOOST_CHECK(!eng.stored(id));
        } else if (std::string(id) == "NIF-PKG-001") {
            BOOST_CHECK(!eng.Apply(id, text, aux, true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK(eng.text_of(id).empty());
            BOOST_CHECK(!eng.Apply(id, other, aux, true, err));
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.stored(id));
        } else {
            BOOST_CHECK(eng.Apply(id, text, aux, true, err));
            BOOST_CHECK(err.empty());
            BOOST_CHECK(eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text_of(id), text);
            BOOST_CHECK_EQUAL(eng.aux_of(id), aux);
            const int64_t again = aux == static_cast<int64_t>(0) ? static_cast<int64_t>(1) : static_cast<int64_t>(0);
            BOOST_CHECK(!eng.Apply(id, text, again, true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
            BOOST_CHECK_EQUAL(err, "REPLAY");
            BOOST_CHECK_EQUAL(eng.text_of(id), text);
            BOOST_CHECK_EQUAL(eng.aux_of(id), aux);
            BOOST_CHECK(!eng.Apply(id, "", aux, true, err));
            BOOST_CHECK_EQUAL(err, "FIELD");
            BOOST_CHECK_EQUAL(eng.text_of(id), text);
            BOOST_CHECK(!eng.Apply(id, other, aux, true, err));
            BOOST_CHECK_EQUAL(err, "UNCHANGED");
            BOOST_CHECK_EQUAL(eng.text_of(id), text);
            BOOST_CHECK_EQUAL(eng.aux_of(id), aux);
            BOOST_CHECK(eng.stored(id));
        }
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK(!eng.release_qualified());
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(17));
    BOOST_CHECK(eng.stored("NIF-ISL-003"));
    BOOST_CHECK_EQUAL(eng.aux_of("NIF-ISL-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.stored("NIF-ISL-004"));
    BOOST_CHECK_EQUAL(eng.aux_of("NIF-ISL-004"), static_cast<int64_t>(100));
    BOOST_CHECK(!eng.stored("NIF-PKG-001"));
    BOOST_CHECK(!eng.stored("NIF-ECON-004"));

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.stored("NIF-QA-003"));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-QA-003"), "note-NIF-QA-003");
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(17));

    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");

    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());

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
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(17));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
