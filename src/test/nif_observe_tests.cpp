// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_observe/nif_observe.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_observe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_ticks_observe_one_admit_spend_stays_and_gpu_absent)
{
    modelnet::NifObserve observe;
    std::string err;

    BOOST_CHECK_EQUAL(observe.ticks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.balance(), static_cast<int64_t>(0));

    BOOST_CHECK(observe.Tick(static_cast<int64_t>(10), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(observe.Tick(static_cast<int64_t>(11), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(observe.ticks(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(0));
    BOOST_CHECK(observe.observed_id().empty());
    BOOST_CHECK_EQUAL(observe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.balance(), static_cast<int64_t>(0));

    BOOST_CHECK(!observe.Admit("", err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(observe.Admit("req-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(0));
    BOOST_CHECK(!observe.Admit("req-1", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(0));
    BOOST_CHECK(observe.observed_id().empty());

    BOOST_CHECK(observe.Tick(static_cast<int64_t>(12), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(observe.observed_id(), "req-1");
    BOOST_CHECK_EQUAL(observe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.ticks(), static_cast<int64_t>(3));

    BOOST_CHECK(observe.Tick(static_cast<int64_t>(13), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(observe.observed_id(), "req-1");
    BOOST_CHECK_EQUAL(observe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.ticks(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(observe.balance(), static_cast<int64_t>(0));

    const int64_t balance_before = observe.balance();
    BOOST_CHECK(!observe.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(observe.balance(), balance_before);
    BOOST_CHECK_EQUAL(observe.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(observe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(1));

    BOOST_CHECK(!observe.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!observe.gpu());
    BOOST_CHECK(!observe.launched());
    BOOST_CHECK(!observe.broadcast());
    BOOST_CHECK_EQUAL(observe.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(observe.observed(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
