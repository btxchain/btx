// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp39/grp39.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp39& eng)
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
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
}

const char* const kIds[] = {
    "DS-PLAN-004",
    "DS-PLAN-005",
    "DS-PLAN-006",
    "DS-ACT-001",
    "DS-ACT-002",
    "DS-ACT-003",
    "DS-ACT-004",
    "DS-ACT-005",
    "DS-ACT-006",
    "DS-SHARE-001",
    "DS-SHARE-002",
    "DS-SHARE-003",
    "DS-SHARE-004",
    "DS-SHARE-005",
    "DS-SHARE-006",
    "DS-STD-001",
    "DS-STD-002",
    "DS-STD-003",
    "DS-STD-004",
    "DS-STD-005",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp39_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rejects_before_store)
{
    modelnet::Grp39 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");

    BOOST_CHECK(!eng.Apply("DS-NO-SUCH", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DS-NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.aux_of("DS-NO-SUCH"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");

    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-004"), "");

    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "row", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));

    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));

    BOOST_CHECK(!modelnet::NifDtEngineLinked("vllm"));
    BOOST_CHECK(!modelnet::NifDtEngineLinked("nixl"));
    BOOST_CHECK(!modelnet::NifDtEngineLinked("rdma"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "nixl", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "rdma", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));

    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "contains private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));

    BOOST_CHECK(eng.Apply("DS-PLAN-004", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DS-PLAN-004"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-004"), "row");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-PLAN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_id_replay_and_release)
{
    modelnet::Grp39 eng;
    std::string err = "stale";
    for (const char* id : kIds) {
        if (std::string(id) == "DS-SHARE-002") {
            BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "EMBARGO");
            BOOST_CHECK(!eng.stored(id));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(0));
            continue;
        }
        const int64_t aux = std::string(id) == "DS-PLAN-005" ? static_cast<int64_t>(100) : static_cast<int64_t>(1);
        BOOST_CHECK(eng.Apply(id, "row", aux, true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "row");
        BOOST_CHECK_EQUAL(eng.aux_of(id), aux);

        BOOST_CHECK(!eng.Apply(id, "row", static_cast<int64_t>(2), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text_of(id), "row");
        BOOST_CHECK_EQUAL(eng.aux_of(id), aux);

        BOOST_CHECK(!eng.Apply(id, "other", aux, true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "row");
        BOOST_CHECK_EQUAL(eng.aux_of(id), aux);
    }

    BOOST_CHECK(!eng.stored("DS-SHARE-002"));
    BOOST_CHECK(eng.stored("DS-ACT-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "row");
    BOOST_CHECK(eng.stored("DS-STD-005"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.stored("DS-PLAN-004"));
    BOOST_CHECK(!eng.stored("DS-SHARE-002"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(d3_approval_stores_nothing)
{
    modelnet::Grp39 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-ACT-002", "D3", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK(!eng.stored("DS-ACT-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-ACT-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-ACT-002", "D3", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK(!eng.stored("DS-ACT-002"));

    BOOST_CHECK(eng.Apply("DS-ACT-002", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DS-ACT-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "row");

    BOOST_CHECK(!eng.Apply("DS-ACT-002", "D3", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK_EQUAL(eng.text_of("DS-ACT-002"), "row");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-ACT-002"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(share_embargo_stores_nothing)
{
    modelnet::Grp39 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-SHARE-002"));
    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-SHARE-002"));

    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "EMBARGO");
    BOOST_CHECK(!eng.stored("DS-SHARE-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-002"), "");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-SHARE-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-SHARE-002", "other", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "EMBARGO");
    BOOST_CHECK(!eng.stored("DS-SHARE-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-SHARE-002"), "");

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
