// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_share/dt_share.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_share_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_self_and_unbound_store_nothing)
{
    modelnet::DtShare share;
    std::string err = "prior";

    BOOST_CHECK(!share.qualified_v41());
    BOOST_CHECK(!share.launched());
    BOOST_CHECK(!share.gpu());
    BOOST_CHECK(!share.broadcast());
    BOOST_CHECK_EQUAL(share.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(share.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(share.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(share.pending("w"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 0);
    BOOST_CHECK_EQUAL(share.consumer_count("w"), 0);
    BOOST_CHECK(!share.detached("w"));

    BOOST_CHECK(!share.Bind("", "c0", err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_OWNER);
    BOOST_CHECK_EQUAL(share.optimizer_owners(""), 0);
    BOOST_CHECK(share.owner_of("c0").empty());

    BOOST_CHECK(!share.Bind("w", "", err));
    BOOST_CHECK_EQUAL(err, "CONSUMER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_CONSUMER);
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 0);
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Bind("w", "w", err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_SELF);
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 0);
    BOOST_CHECK(share.owner_of("w").empty());
    BOOST_CHECK_EQUAL(share.consumer_count("w"), 0);

    BOOST_CHECK(!share.Grad("w", "c0", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "CONSUMER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_CONSUMER);
    BOOST_CHECK_EQUAL(share.pending("w"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Apply("w", err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_OWNER);
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Apply("", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_OWNER);

    BOOST_CHECK(!share.Detach("missing", err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK(!share.detached("missing"));
    BOOST_CHECK_EQUAL(share.weight("missing"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.CacheGrad("missing", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_OWNER);
    BOOST_CHECK_EQUAL(share.weight("missing"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!share.gpu());
    BOOST_CHECK(!share.launched());
    BOOST_CHECK(!share.broadcast());
    BOOST_CHECK(!share.qualified_v41());
    BOOST_CHECK_EQUAL(share.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(share.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(two_consumers_apply_once_replay_and_detached_cache)
{
    modelnet::DtShare share;
    std::string err = "prior";

    BOOST_CHECK(share.Bind("w", "c0", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(share.Bind("w", "c1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(share.owner_of("c0"), "w");
    BOOST_CHECK_EQUAL(share.owner_of("c1"), "w");
    BOOST_CHECK_EQUAL(share.consumer_count("w"), 2);
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 1);
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Bind("other", "c0", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(share.owner_of("c0"), "w");
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 1);
    BOOST_CHECK_EQUAL(share.optimizer_owners("other"), 0);
    BOOST_CHECK_EQUAL(share.consumer_count("w"), 2);

    BOOST_CHECK(!share.Bind("w", "c0", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(share.owner_of("c0"), "w");
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 1);

    BOOST_CHECK(!share.Grad("nope", "c0", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_CONSUMER);
    BOOST_CHECK_EQUAL(share.pending("w"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Apply("w", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_UNCHANGED);
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));

    BOOST_CHECK(share.Grad("w", "c0", static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(share.pending("w"), static_cast<int64_t>(2));
    BOOST_CHECK(share.Grad("w", "c1", static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(share.pending("w"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 1);

    BOOST_CHECK(share.Apply("w", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(share.pending("w"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Grad("w", "c0", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(share.pending("w"), static_cast<int64_t>(0));
    BOOST_CHECK(!share.Apply("w", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_UNCHANGED);
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(share.bytes_moved(), static_cast<int64_t>(0));

    const std::int64_t before_detach = share.weight("w");
    BOOST_CHECK(share.Detach("w", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(share.detached("w"));
    BOOST_CHECK_EQUAL(share.weight("w"), before_detach);
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(6));

    BOOST_CHECK(!share.CacheGrad("w", err));
    BOOST_CHECK_EQUAL(err, "DETACHED");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_DETACHED);
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(share.weight("w"), before_detach);
    BOOST_CHECK_EQUAL(share.optimizer_owners("w"), 1);

    BOOST_CHECK(!share.Detach("w", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(share.detached("w"));
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(6));

    BOOST_CHECK(!share.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(share.weight("w"), static_cast<int64_t>(6));
    BOOST_CHECK(!share.gpu());
    BOOST_CHECK(!share.launched());
    BOOST_CHECK(!share.broadcast());
    BOOST_CHECK(!share.qualified_v41());
    BOOST_CHECK_EQUAL(share.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(share.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(attached_cache_folds_once)
{
    modelnet::DtShare share;
    std::string err = "prior";

    BOOST_CHECK(share.Bind("a", "k", err));
    BOOST_CHECK(share.Grad("a", "k", static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(share.pending("a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(share.weight("a"), static_cast<int64_t>(0));
    BOOST_CHECK(!share.detached("a"));

    BOOST_CHECK(share.CacheGrad("a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(share.weight("a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(share.pending("a"), static_cast<int64_t>(0));

    BOOST_CHECK(!share.Apply("a", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_SHARE_UNCHANGED);
    BOOST_CHECK_EQUAL(share.weight("a"), static_cast<int64_t>(5));

    BOOST_CHECK(!share.CacheGrad("a", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(share.weight("a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(share.optimizer_owners("a"), 1);
    BOOST_CHECK_EQUAL(share.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!share.qualified_v41());
}

BOOST_AUTO_TEST_SUITE_END()
