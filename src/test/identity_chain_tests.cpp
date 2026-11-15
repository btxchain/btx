// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/identity_chain/identity_chain.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::IdentityChainRecord& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(identity_chain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_field)
{
    modelnet::IdentityChainRecord eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Open("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(err, modelnet::IDENTITY_CHAIN_FIELD);
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK_EQUAL(eng.epoch(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Open("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(open_sets_epoch_one)
{
    modelnet::IdentityChainRecord eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Open("alpha", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("alpha"));
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Open("alpha", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK(eng.stored("alpha"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(expiry_equality_does_not_advance)
{
    modelnet::IdentityChainRecord eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Open("alpha", err));
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(1));

    const int64_t now_ms = static_cast<int64_t>(5000);
    BOOST_CHECK(!eng.Rotate("alpha", now_ms, now_ms, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(err, modelnet::IDENTITY_CHAIN_EXPIRED);
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(1));

    const int64_t earlier = now_ms - static_cast<int64_t>(1);
    BOOST_CHECK(!eng.Rotate("alpha", now_ms, earlier, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK(eng.stored("alpha"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(rotate_advances_to_epoch_two)
{
    modelnet::IdentityChainRecord eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Open("alpha", err));
    BOOST_CHECK(eng.Open("beta", err));
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.epoch("beta"), static_cast<int64_t>(1));

    const int64_t now_ms = static_cast<int64_t>(5000);
    const int64_t until_ms = now_ms + static_cast<int64_t>(1);
    BOOST_CHECK(eng.Rotate("alpha", now_ms, until_ms, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.epoch("beta"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(stale_recover_keeps_epoch)
{
    modelnet::IdentityChainRecord eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Open("alpha", err));
    const int64_t now_ms = static_cast<int64_t>(8000);
    const int64_t until_ms = now_ms + static_cast<int64_t>(1);
    BOOST_CHECK(eng.Rotate("alpha", now_ms, until_ms, err));
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(2));

    BOOST_CHECK(!eng.Recover("alpha", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(err, modelnet::IDENTITY_CHAIN_STALE);
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(2));

    BOOST_CHECK(eng.Recover("alpha", static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(2));

    BOOST_CHECK(!eng.Recover("alpha", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "EPOCH");
    BOOST_CHECK_EQUAL(err, modelnet::IDENTITY_CHAIN_EPOCH);
    BOOST_CHECK_EQUAL(eng.epoch("alpha"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(unknown_id_is_identity)
{
    modelnet::IdentityChainRecord eng;
    std::string err = "stale";
    const int64_t now_ms = static_cast<int64_t>(1000);
    const int64_t until_ms = now_ms + static_cast<int64_t>(1);
    BOOST_CHECK(!eng.Rotate("missing", now_ms, until_ms, err));
    BOOST_CHECK_EQUAL(err, "IDENTITY");
    BOOST_CHECK_EQUAL(err, modelnet::IDENTITY_CHAIN_IDENTITY);
    BOOST_CHECK(!eng.stored("missing"));
    BOOST_CHECK_EQUAL(eng.epoch("missing"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Rotate("missing", now_ms, now_ms, err));
    BOOST_CHECK_EQUAL(err, "IDENTITY");
    BOOST_CHECK(!eng.stored("missing"));

    BOOST_CHECK(!eng.Recover("missing", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "IDENTITY");
    BOOST_CHECK_EQUAL(eng.epoch("missing"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
