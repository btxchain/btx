// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp38/grp38.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp38& eng)
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
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

const char* const kIds[] = {
    "DS-HIRE-002",
    "DS-HIRE-003",
    "DS-HIRE-004",
    "DS-HIRE-005",
    "DS-HIRE-006",
    "DS-AUTH-001",
    "DS-AUTH-002",
    "DS-AUTH-003",
    "DS-AUTH-004",
    "DS-AUTH-005",
    "DS-AUTH-006",
    "DS-DATA-001",
    "DS-DATA-002",
    "DS-DATA-003",
    "DS-DATA-004",
    "DS-DATA-005",
    "DS-DATA-006",
    "DS-PLAN-001",
    "DS-PLAN-002",
    "DS-PLAN-003",
};

const char* const kRemote[] = {
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp38_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_or_empty_id)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));

    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DS-HIRE-001"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-004", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DS-PLAN-004"));
    BOOST_CHECK(!eng.Apply("nope", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("nope"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(empty_text_is_field)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-HIRE-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "", static_cast<int64_t>(-5), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-HIRE-002"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-AUTH-003"));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(aux_bound_and_cap)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-HIRE-002"));
    BOOST_CHECK(!eng.Apply("DS-PLAN-001", "row", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-PLAN-001"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "lease", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-AUTH-003"));

    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "row", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DS-HIRE-002"));
    BOOST_CHECK(!eng.Apply("DS-DATA-001", "row", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DS-DATA-001"));

    BOOST_CHECK(eng.Apply("DS-HIRE-002", "row", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "row");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-HIRE-002"), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Apply("DS-PLAN-001", "span", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-001"), "span");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-PLAN-001"), static_cast<int64_t>(100));

    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "row", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "row");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-HIRE-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-PLAN-001", "span", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-001"), "span");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-PLAN-001"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(flag_false_is_absent)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-DATA-002", "row", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-DATA-002"));
    BOOST_CHECK(!eng.Apply("DS-DATA-002", "nixl", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-DATA-002"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "lease", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-AUTH-003"));

    BOOST_CHECK(eng.Apply("DS-DATA-002", "row", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-002"), "row");
    BOOST_CHECK(!eng.Apply("DS-DATA-002", "other", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-002"), "row");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-DATA-002"), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_names_are_engine_absent)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    for (const char* name : kRemote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("DS-HIRE-004", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("DS-HIRE-004"));
        BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-004"), "");
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.launched());
    }
    BOOST_CHECK(eng.Apply("DS-HIRE-004", "local", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-004"), "local");
    BOOST_CHECK(!eng.Apply("DS-HIRE-004", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-004"), "local");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_text_is_refused)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-DATA-004"));
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "has private inside", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-DATA-004"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Apply("DS-DATA-004", "public", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-004"), "public");
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "still private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-004"), "public");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-DATA-004"), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    for (const char* id : kIds) {
        BOOST_CHECK(eng.Apply(id, "kept", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "kept");
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(1));
        BOOST_CHECK(!eng.Apply(id, "kept", static_cast<int64_t>(2), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text_of(id), "kept");
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(1));
        BOOST_CHECK(!eng.Apply(id, "other", static_cast<int64_t>(3), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text_of(id), "kept");
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(1));
        BOOST_CHECK(!eng.Apply(id, "", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "FIELD");
        BOOST_CHECK_EQUAL(eng.text_of(id), "kept");
    }
    BOOST_CHECK(eng.stored("DS-HIRE-002"));
    BOOST_CHECK(eng.stored("DS-HIRE-003"));
    BOOST_CHECK(eng.stored("DS-HIRE-004"));
    BOOST_CHECK(eng.stored("DS-HIRE-005"));
    BOOST_CHECK(eng.stored("DS-HIRE-006"));
    BOOST_CHECK(eng.stored("DS-AUTH-001"));
    BOOST_CHECK(eng.stored("DS-AUTH-002"));
    BOOST_CHECK(eng.stored("DS-AUTH-003"));
    BOOST_CHECK(eng.stored("DS-AUTH-004"));
    BOOST_CHECK(eng.stored("DS-AUTH-005"));
    BOOST_CHECK(eng.stored("DS-AUTH-006"));
    BOOST_CHECK(eng.stored("DS-DATA-001"));
    BOOST_CHECK(eng.stored("DS-DATA-002"));
    BOOST_CHECK(eng.stored("DS-DATA-003"));
    BOOST_CHECK(eng.stored("DS-DATA-004"));
    BOOST_CHECK(eng.stored("DS-DATA-005"));
    BOOST_CHECK(eng.stored("DS-DATA-006"));
    BOOST_CHECK(eng.stored("DS-PLAN-001"));
    BOOST_CHECK(eng.stored("DS-PLAN-002"));
    BOOST_CHECK(eng.stored("DS-PLAN-003"));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(auth_003_expiry)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "lease", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!eng.stored("DS-AUTH-003"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-AUTH-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "lease", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-AUTH-003"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "nixl", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.stored("DS-AUTH-003"));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "private", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DS-AUTH-003"));

    BOOST_CHECK(eng.Apply("DS-AUTH-003", "lease", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("DS-AUTH-003"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-AUTH-003"), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "lease", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-AUTH-003"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "other", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");

    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "lease", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "other", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-AUTH-003"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_rejects_a_second_host)
{
    modelnet::Grp38 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("DS-PLAN-003", "kept", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-PLAN-003"), "kept");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
