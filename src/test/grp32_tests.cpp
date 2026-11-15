// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp32/grp32.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp32& eng)
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

void ExpectAbsent(modelnet::Grp32& eng, const std::string& name)
{
    std::string err = "stale";
    BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
    BOOST_CHECK(!eng.Note(name, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(eng.Absent(name));
    BOOST_CHECK(!eng.linked(name));
    BOOST_CHECK(!eng.Note(name, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.Absent(name));
    BOOST_CHECK(!eng.linked(name));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_name)
{
    modelnet::Grp32 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Note("", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.Absent(""));
    BOOST_CHECK(!eng.linked(""));
    BOOST_CHECK(!eng.Note("", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!eng.Absent(""));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(unlinked_names_are_absent)
{
    modelnet::Grp32 eng;
    ExpectAbsent(eng, "deepinfer");
    ExpectAbsent(eng, "vllm");
    ExpectAbsent(eng, "rdma");
    ExpectAbsent(eng, "dualpipe");
    ExpectAbsent(eng, "nixl");
    ExpectAbsent(eng, "mooncake");
    BOOST_CHECK(eng.Absent("deepinfer"));
    BOOST_CHECK(eng.Absent("vllm"));
    BOOST_CHECK(eng.Absent("rdma"));
    BOOST_CHECK(eng.Absent("dualpipe"));
    BOOST_CHECK(eng.Absent("nixl"));
    BOOST_CHECK(eng.Absent("mooncake"));
    BOOST_CHECK(!eng.linked("deepinfer"));
    BOOST_CHECK(!eng.linked("rdma"));
    BOOST_CHECK(!eng.linked("dualpipe"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(fp8_is_engine_absent)
{
    modelnet::Grp32 eng;
    std::string err = "stale";
    BOOST_CHECK(modelnet::NifDtEngineLinked("fp8"));
    BOOST_CHECK(!eng.Note("fp8", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(eng.Absent("fp8"));
    BOOST_CHECK(!eng.linked("fp8"));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Note("fp8", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(eng.Absent("fp8"));
    BOOST_CHECK(!eng.linked("fp8"));

    BOOST_CHECK(modelnet::NifDtEngineLinked("offline"));
    BOOST_CHECK(!eng.Note("offline", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(eng.Absent("offline"));
    BOOST_CHECK(!eng.linked("offline"));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(memory_and_local_are_linked)
{
    modelnet::Grp32 eng;
    std::string err = "stale";
    BOOST_CHECK(modelnet::NifDtEngineLinked("memory"));
    BOOST_CHECK(modelnet::NifDtEngineLinked("local"));
    BOOST_CHECK(eng.Note("memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.linked("memory"));
    BOOST_CHECK(!eng.Absent("memory"));
    BOOST_CHECK(!eng.Note("memory", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(eng.linked("memory"));
    BOOST_CHECK(!eng.Absent("memory"));

    BOOST_CHECK(eng.Note("local", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.linked("local"));
    BOOST_CHECK(!eng.Absent("local"));
    BOOST_CHECK(!eng.Note("local", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.linked("memory"));
    BOOST_CHECK(eng.linked("local"));

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(eng.linked("memory"));
    BOOST_CHECK(eng.linked("local"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_rejects_a_second_host)
{
    modelnet::Grp32 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Note("memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.linked("memory"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
