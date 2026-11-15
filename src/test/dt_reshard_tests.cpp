// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_reshard/dt_reshard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectIdle(const modelnet::DtReshard& reshard)
{
    BOOST_CHECK(!reshard.launched());
    BOOST_CHECK(!reshard.gpu());
    BOOST_CHECK(!reshard.broadcast());
    BOOST_CHECK(!reshard.qualified());
    BOOST_CHECK_EQUAL(reshard.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_reshard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(map_w_mismatch_then_apply_once)
{
    modelnet::DtReshard reshard;
    std::string err;
    BOOST_CHECK(reshard.Map("w", "s0", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!reshard.Move("w", "s1", 5, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(reshard.Move("w", "s0", 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(reshard.Apply("w", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(!reshard.Apply("w", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(!reshard.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    ExpectIdle(reshard);
}

BOOST_AUTO_TEST_CASE(empty_replay_and_unknown_store_nothing)
{
    modelnet::DtReshard reshard;
    std::string err = "stale";
    BOOST_CHECK(!reshard.Map("", "s0", err));
    BOOST_CHECK_EQUAL(err, "PARAM");
    BOOST_CHECK(!reshard.Map("w", "", err));
    BOOST_CHECK_EQUAL(err, "SHARD");
    BOOST_CHECK(!reshard.Move("w", "s0", 5, err));
    BOOST_CHECK_EQUAL(err, "PARAM");
    BOOST_CHECK(!reshard.Apply("w", err));
    BOOST_CHECK_EQUAL(err, "UNMAPPED");
    BOOST_CHECK(!reshard.Prior("", err));
    BOOST_CHECK_EQUAL(err, "PARAM");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(reshard.Map("w", "s0", err));
    BOOST_CHECK(!reshard.Map("w", "s1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!reshard.Move("w", "s1", 5, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(!reshard.Apply("w", err));
    BOOST_CHECK_EQUAL(err, "UNMAPPED");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(reshard.Prior("w", err));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    ExpectIdle(reshard);
}

BOOST_AUTO_TEST_CASE(mismatch_keeps_stored_weight)
{
    modelnet::DtReshard reshard;
    std::string err;
    BOOST_CHECK(reshard.Map("w", "s0", err));
    BOOST_CHECK(reshard.Move("w", "s0", 4, err));
    BOOST_CHECK(!reshard.Move("w", "s1", 9, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(reshard.Apply("w", err));
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(!reshard.Move("w", "s1", 9, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    ExpectIdle(reshard);
}

BOOST_AUTO_TEST_CASE(prior_survives_failed_move_until_next_apply)
{
    modelnet::DtReshard reshard;
    std::string err;
    BOOST_CHECK(reshard.Map("w", "s0", err));
    BOOST_CHECK(reshard.Prior("w", err));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(!reshard.Move("w", "s1", 5, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(reshard.Move("w", "s0", 5, err));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(reshard.Apply("w", err));
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(reshard.Prior("w", err));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(!reshard.Move("w", "s1", 8, err));
    BOOST_CHECK_EQUAL(err, "MAP");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(reshard.Move("w", "s0", 8, err));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(reshard.Apply("w", err));
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(5));
    BOOST_CHECK(!reshard.Apply("w", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(reshard.live_weight(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(reshard.prior_weight(), static_cast<int64_t>(5));
    ExpectIdle(reshard);
}

BOOST_AUTO_TEST_SUITE_END()
