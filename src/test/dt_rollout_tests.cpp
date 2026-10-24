// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_rollout/dt_rollout.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_rollout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_full_samples_replenish_early_excluded_and_generate_waits_for_seal)
{
    modelnet::DtRollout rollout;
    std::string err;

    BOOST_CHECK(!rollout.launched());
    BOOST_CHECK(!rollout.gpu());
    BOOST_CHECK(!rollout.broadcast());
    BOOST_CHECK(!rollout.generate_dropped_train());
    BOOST_CHECK(!rollout.replenished());
    BOOST_CHECK(!rollout.sealed());
    BOOST_CHECK(!rollout.generating());
    BOOST_CHECK_EQUAL(rollout.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(rollout.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rollout.short_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rollout.routed_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rollout.tokens_of("missing"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rollout.version_of("missing"), static_cast<uint64_t>(0));

    // The replenishment starts open. Generate before Seal is MODE.
    BOOST_CHECK(!rollout.SwitchGenerate(err));
    BOOST_CHECK_EQUAL(err, "MODE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_ROLLOUT_MODE);
    BOOST_CHECK(!rollout.generating());
    BOOST_CHECK(!rollout.generate_dropped_train());
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!rollout.Route("", static_cast<uint64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK_EQUAL(rollout.routed_count(), static_cast<int64_t>(0));

    // An incompatible route stores nothing.
    BOOST_CHECK(!rollout.Route("bad", static_cast<uint64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!rollout.has_sample("bad"));
    BOOST_CHECK_EQUAL(rollout.version_of("bad"), static_cast<uint64_t>(0));
    BOOST_CHECK_EQUAL(rollout.routed_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(0));

    BOOST_CHECK(rollout.Route("s1", static_cast<uint64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rollout.Route("s2", static_cast<uint64_t>(7), true, err));
    BOOST_CHECK_EQUAL(rollout.version_of("s1"), static_cast<uint64_t>(4));
    BOOST_CHECK_EQUAL(rollout.version_of("s2"), static_cast<uint64_t>(7));
    BOOST_CHECK_EQUAL(rollout.routed_count(), static_cast<int64_t>(2));

    // A duplicate keeps the first version.
    BOOST_CHECK(!rollout.Route("s1", static_cast<uint64_t>(99), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(rollout.version_of("s1"), static_cast<uint64_t>(4));
    BOOST_CHECK_EQUAL(rollout.routed_count(), static_cast<int64_t>(2));
    BOOST_CHECK(!rollout.Route("s1", static_cast<uint64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(rollout.version_of("s1"), static_cast<uint64_t>(4));

    BOOST_CHECK(!rollout.Finish("nope", static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "SAMPLE");
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!rollout.Finish("s1", static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LENGTH");
    BOOST_CHECK(!rollout.finished("s1"));
    BOOST_CHECK_EQUAL(rollout.tokens_of("s1"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!rollout.Replenish(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "LENGTH");
    BOOST_CHECK(!rollout.replenished());

    // One early sample is stored as short and does not count.
    BOOST_CHECK(rollout.Route("early", static_cast<uint64_t>(1), true, err));
    BOOST_CHECK(rollout.Finish("early", static_cast<int64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rollout.has_sample("early"));
    BOOST_CHECK(rollout.is_short("early"));
    BOOST_CHECK(!rollout.finished("early"));
    BOOST_CHECK_EQUAL(rollout.tokens_of("early"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(rollout.short_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!rollout.Replenish(static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!rollout.replenished());

    // Two full samples of 4 tokens replenish a need of 2.
    BOOST_CHECK(rollout.Finish("s1", static_cast<int64_t>(4), false, err));
    BOOST_CHECK(rollout.Finish("s2", static_cast<int64_t>(4), false, err));
    BOOST_CHECK(rollout.finished("s1"));
    BOOST_CHECK(rollout.finished("s2"));
    BOOST_CHECK(!rollout.is_short("s1"));
    BOOST_CHECK_EQUAL(rollout.tokens_of("s1"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(rollout.tokens_of("s2"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(rollout.short_count(), static_cast<int64_t>(1));

    // A second finish keeps the first tokens.
    BOOST_CHECK(!rollout.Finish("s1", static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(rollout.finished("s1"));
    BOOST_CHECK(!rollout.is_short("s1"));
    BOOST_CHECK_EQUAL(rollout.tokens_of("s1"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(2));

    BOOST_CHECK(!rollout.Replenish(static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!rollout.replenished());
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(2));

    BOOST_CHECK(rollout.Replenish(static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rollout.replenished());
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(2));

    // Switching to generate before seal is MODE and the finished count stays.
    const int64_t finished = rollout.finished_count();
    const int64_t shorts = rollout.short_count();
    BOOST_CHECK(!rollout.SwitchGenerate(err));
    BOOST_CHECK_EQUAL(err, "MODE");
    BOOST_CHECK_EQUAL(rollout.finished_count(), finished);
    BOOST_CHECK_EQUAL(rollout.short_count(), shorts);
    BOOST_CHECK_EQUAL(rollout.finished_count(), static_cast<int64_t>(2));
    BOOST_CHECK(rollout.has_sample("s1"));
    BOOST_CHECK(rollout.has_sample("s2"));
    BOOST_CHECK(rollout.has_sample("early"));
    BOOST_CHECK_EQUAL(rollout.tokens_of("s1"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(rollout.version_of("s1"), static_cast<uint64_t>(4));
    BOOST_CHECK(!rollout.generating());
    BOOST_CHECK(!rollout.generate_dropped_train());
    BOOST_CHECK(!rollout.sealed());

    BOOST_CHECK(rollout.Seal(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rollout.sealed());
    BOOST_CHECK(rollout.SwitchGenerate(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(rollout.generating());
    BOOST_CHECK(!rollout.generate_dropped_train());
    BOOST_CHECK_EQUAL(rollout.finished_count(), finished);
    BOOST_CHECK_EQUAL(rollout.short_count(), shorts);
    BOOST_CHECK(rollout.has_sample("s1"));
    BOOST_CHECK(rollout.has_sample("s2"));
    BOOST_CHECK_EQUAL(rollout.tokens_of("s2"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(rollout.version_of("s1"), static_cast<uint64_t>(4));
    BOOST_CHECK(rollout.replenished());

    BOOST_CHECK(!rollout.launched());
    BOOST_CHECK(!rollout.gpu());
    BOOST_CHECK(!rollout.broadcast());
    BOOST_CHECK_EQUAL(rollout.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
