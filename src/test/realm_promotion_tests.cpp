// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/realm_promotion/realm_promotion.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::RealmPromotion& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(realm_promotion_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_stored_candidate)
{
    modelnet::RealmPromotion eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Propose("promo-a", "one", err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK(!eng.stored("promo-a"));
    BOOST_CHECK(eng.text("promo-a").empty());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(eng.Propose("promo-a", "candidate-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("promo-a"));
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.stored("promo-b"));
    BOOST_CHECK(eng.text("promo-b").empty());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Propose("promo-a", "one", err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK(eng.stored("promo-a"));
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.qualified());

    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(eng.stored("promo-a"));
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(empty_private_and_engines_store_nothing)
{
    modelnet::RealmPromotion eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Propose("", "candidate-a", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("promo-a"));
    BOOST_CHECK(!eng.Propose("promo-a", "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("promo-a"));
    BOOST_CHECK(!eng.Propose("", "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.qualified());

    BOOST_CHECK(!eng.Propose("promo-a", "private", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("promo-a"));
    BOOST_CHECK(!eng.Propose("promo-a", "candidate-private", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("promo-a"));

    const char* const engines[] = {
        "vllm",
        "sglang",
        "lmcache",
        "nixl",
        "mooncake",
        "rdma",
        "deepinfer",
        "dualpipe",
        "fp8",
        "fp4",
    };
    for (const char* name : engines) {
        BOOST_CHECK(!eng.Propose("promo-a", name, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK(!eng.stored("promo-a"));
        BOOST_CHECK(!eng.gpu());
        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK(!eng.passed());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK(eng.Propose("promo-a", "candidate-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.Propose("promo-a", "private", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.Propose("promo-a", "fp8", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(replay_unchanged_and_hosts)
{
    modelnet::RealmPromotion eng;
    std::string err = "stale";

    BOOST_CHECK(eng.Propose("promo-a", "candidate-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Propose("promo-a", "candidate-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.Propose("promo-b", "candidate-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(!eng.stored("promo-b"));
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.Propose("promo-a", "candidate-b", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    BOOST_CHECK(!eng.Propose("promo-b", "candidate-b", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK(eng.stored("promo-a"));
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK_EQUAL(eng.text("promo-a"), "candidate-a");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
