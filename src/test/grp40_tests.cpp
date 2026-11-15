// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp40/grp40.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp40& eng)
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
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
}

struct IdRow {
    const char* id;
    bool unqualified;
};

const IdRow kIds[] = {
    {"DS-STD-006", false},
    {"DS-MODEL-001", false},
    {"DS-MODEL-002", false},
    {"DS-MODEL-003", false},
    {"DS-MODEL-004", false},
    {"DS-MODEL-005", false},
    {"DS-MODEL-006", false},
    {"DS-LEARN-001", false},
    {"DS-LEARN-002", false},
    {"DS-LEARN-003", false},
    {"DS-LEARN-004", false},
    {"DS-LEARN-005", false},
    {"DS-LEARN-006", true},
    {"DS-POOL-001", false},
    {"DS-POOL-002", false},
    {"DS-POOL-003", false},
    {"DS-POOL-004", false},
    {"DS-POOL-005", false},
    {"DS-POOL-006", false},
    {"DS-PAY-001", true},
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp40_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_or_unknown_id)
{
    modelnet::Grp40 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP40_ID);
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("DS-STD-001", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DS-STD-001"));
    BOOST_CHECK(!eng.Apply("DS-PAY-002", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP40_ID);
    BOOST_CHECK(!eng.stored("DS-PAY-002"));
    BOOST_CHECK(!eng.Apply("rdma", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("rdma"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(field_bound_cap_and_absent_precede_later_refusals)
{
    modelnet::Grp40 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP40_FIELD);
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-MODEL-001"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");

    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "note", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP40_BOUND);
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-MODEL-001"));
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "note", static_cast<int64_t>(-5), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-PAY-001"));

    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "note", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP40_CAP);
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DS-MODEL-001"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "note", static_cast<int64_t>(1000), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DS-LEARN-006"));

    BOOST_CHECK(!modelnet::NifDtEngineLinked("rdma"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "rdma", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP40_ABSENT);
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-MODEL-001"));
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "a private note", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-PAY-001"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_names_and_private_text_store_nothing)
{
    modelnet::Grp40 eng;
    std::string err = "stale";
    const char* remote[] = {
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
    for (const char* name : remote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("DS-STD-006", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("DS-STD-006"));
    }
    BOOST_CHECK(!eng.Apply("DS-MODEL-002", "keep private context", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-MODEL-002"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "private", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-LEARN-006"));
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "private", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DS-PAY-001"));

    BOOST_CHECK(eng.Apply("DS-STD-006", "typed subset", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DS-STD-006"));
    BOOST_CHECK_EQUAL(eng.text("DS-STD-006"), "typed subset");
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.text("DS-STD-006"), "typed subset");
}

BOOST_AUTO_TEST_CASE(unqualified_ids_store_nothing)
{
    modelnet::Grp40 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "oracle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DS-PAY-001"));
    BOOST_CHECK(eng.text("DS-PAY-001").empty());
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "oracle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DS-PAY-001"));
    BOOST_CHECK(!eng.Apply("DS-PAY-001", "other", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("DS-PAY-001"));

    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "cycle", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DS-LEARN-006"));
    BOOST_CHECK(eng.text("DS-LEARN-006").empty());
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "cycle", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DS-LEARN-006"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_id_stores_once_or_stays_unqualified)
{
    modelnet::Grp40 eng;
    std::string err = "stale";
    int64_t stored_n = static_cast<int64_t>(0);
    for (const IdRow& row : kIds) {
        if (row.unqualified) {
            BOOST_CHECK(!eng.Apply(row.id, "note", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK(!eng.stored(row.id));
            BOOST_CHECK(eng.text(row.id).empty());
            continue;
        }
        BOOST_CHECK(eng.Apply(row.id, "note", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(row.id));
        BOOST_CHECK_EQUAL(eng.text(row.id), "note");
        stored_n += static_cast<int64_t>(1);
        BOOST_CHECK_EQUAL(eng.count(), stored_n);

        BOOST_CHECK(!eng.Apply(row.id, "note", static_cast<int64_t>(100), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text(row.id), "note");
        BOOST_CHECK_EQUAL(eng.count(), stored_n);

        BOOST_CHECK(!eng.Apply(row.id, "other", static_cast<int64_t>(0), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::GRP40_UNCHANGED);
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text(row.id), "note");
        BOOST_CHECK(eng.stored(row.id));
        BOOST_CHECK_EQUAL(eng.count(), stored_n);
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(18));
    BOOST_CHECK(!eng.stored("DS-PAY-001"));
    BOOST_CHECK(!eng.stored("DS-LEARN-006"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(18));
    BOOST_CHECK_EQUAL(eng.text("DS-STD-006"), "note");
    BOOST_CHECK_EQUAL(eng.text("DS-POOL-006"), "note");

    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(18));
    BOOST_CHECK_EQUAL(eng.text("DS-MODEL-006"), "note");
}

BOOST_AUTO_TEST_CASE(hosts_rejects_a_second_host)
{
    modelnet::Grp40 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("DS-POOL-001", "budgets", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP40_HOSTS);
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.stored("DS-POOL-001"));
    BOOST_CHECK_EQUAL(eng.text("DS-POOL-001"), "budgets");
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
