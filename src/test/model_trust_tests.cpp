// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/model_trust/model_trust.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::ModelTrust& eng)
{
    std::string err;
    BOOST_CHECK(!eng.monetary_store());
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
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(model_trust_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_or_digest_is_field)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Attest("", static_cast<int64_t>(1), "digest-1", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.attested(""));
    BOOST_CHECK_EQUAL(eng.sequence(""), static_cast<int64_t>(0));
    BOOST_CHECK(eng.digest("").empty());
    BOOST_CHECK(!eng.Attest("", static_cast<int64_t>(1), "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(1), "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.attested("lane-a"));
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.digest("lane-a").empty());
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(sequence_below_one_is_sequence)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(0), "digest-1", err));
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK(!eng.attested("lane-a"));
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(-1), "digest-1", err));
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK(!eng.attested("lane-a"));
    BOOST_CHECK(eng.digest("lane-a").empty());
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(first_attest_stores_sequence_and_digest)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Attest("lane-a", static_cast<int64_t>(1), "digest-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.attested("lane-a"));
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK(!eng.attested("lane-b"));
    BOOST_CHECK_EQUAL(eng.sequence("lane-b"), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Attest("lane-b", static_cast<int64_t>(4), "digest-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK_EQUAL(eng.sequence("lane-b"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.digest("lane-b"), "digest-b");
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
}

BOOST_AUTO_TEST_CASE(lower_sequence_is_rollback)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Attest("lane-a", static_cast<int64_t>(5), "digest-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(4), "digest-2", err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(1), "digest-1", err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
}

BOOST_AUTO_TEST_CASE(equal_sequence_different_digest_is_mismatch)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Attest("lane-a", static_cast<int64_t>(3), "digest-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(3), "digest-2", err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(3), "digest-9", err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(3));
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(same_sequence_and_digest_is_replay)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Attest("lane-a", static_cast<int64_t>(2), "digest-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(2), "digest-1", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(2), "digest-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.attested("lane-a"));
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(higher_sequence_replaces_then_rollback_and_mismatch)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Attest("lane-a", static_cast<int64_t>(2), "digest-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Attest("lane-a", static_cast<int64_t>(6), "digest-6", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-6");

    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(5), "digest-1", err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-6");

    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(6), "digest-1", err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-6");
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(6));

    BOOST_CHECK(!eng.Attest("lane-a", static_cast<int64_t>(6), "digest-6", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-6");
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(monetary_store_stays_false)
{
    modelnet::ModelTrust eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(eng.Attest("lane-a", static_cast<int64_t>(1), "digest-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.sequence("lane-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.digest("lane-a"), "digest-1");
    BOOST_CHECK(!eng.monetary_store());
    Idle(eng);
    BOOST_CHECK(!eng.monetary_store());
}

BOOST_AUTO_TEST_SUITE_END()
