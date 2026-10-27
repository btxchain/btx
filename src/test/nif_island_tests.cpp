// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_island/nif_island.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_island_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unqualified_hardware_is_not_stored)
{
    modelnet::NifIsland island;
    std::string err;
    BOOST_CHECK(!island.Admit("", static_cast<int64_t>(10), true, err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(!island.Admit("bare", static_cast<int64_t>(10), false, err));
    BOOST_CHECK_EQUAL(err, "HARDWARE");
    BOOST_CHECK(!island.admitted("bare"));
    BOOST_CHECK_EQUAL(island.member_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(island.rtt_us("bare"), static_cast<int64_t>(0));
    BOOST_CHECK(!island.Place("bare", "prefill", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(island.placed("prefill").empty());
    BOOST_CHECK_EQUAL(island.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!island.socket_opened());
}

BOOST_AUTO_TEST_CASE(measured_rtt_is_kept)
{
    modelnet::NifIsland island;
    std::string err;
    BOOST_CHECK(island.Admit("m", static_cast<int64_t>(37), true, err));
    BOOST_CHECK_EQUAL(island.rtt_us("m"), static_cast<int64_t>(37));
    BOOST_CHECK_EQUAL(island.member_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!island.Admit("m", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(island.rtt_us("m"), static_cast<int64_t>(37));
    BOOST_CHECK_EQUAL(island.member_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!island.gpu());
    BOOST_CHECK_EQUAL(island.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(queue_cap_refuses_the_extra_byte)
{
    modelnet::NifIsland island;
    std::string err;
    BOOST_CHECK(island.Admit("q", static_cast<int64_t>(20), true, err));
    BOOST_CHECK_EQUAL(island.queued(), static_cast<int64_t>(0));
    for (int i = 0; i < 8; ++i) {
        BOOST_CHECK(island.Push("q", static_cast<int64_t>(1), err));
    }
    BOOST_CHECK_EQUAL(island.queued(), static_cast<int64_t>(8));
    BOOST_CHECK(!island.Push("q", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "BACKPRESSURE");
    BOOST_CHECK_EQUAL(island.queued(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(island.queued("q"), static_cast<int64_t>(8));

    modelnet::NifIsland bulk;
    BOOST_CHECK(bulk.Admit("q2", static_cast<int64_t>(5), true, err));
    BOOST_CHECK(!bulk.Push("q2", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "BACKPRESSURE");
    BOOST_CHECK_EQUAL(bulk.queued(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(rtt_5000_is_no_route)
{
    modelnet::NifIsland island;
    std::string err;
    BOOST_CHECK(island.Admit("c", static_cast<int64_t>(15), true, err));
    BOOST_CHECK(!island.Collective("c", static_cast<int64_t>(5000), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(island.local_collectives(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(island.last_local_rtt_us(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(island.rtt_us("c"), static_cast<int64_t>(15));
    BOOST_CHECK(!island.gpu());

    BOOST_CHECK(island.Collective("c", static_cast<int64_t>(250), err));
    BOOST_CHECK_EQUAL(island.local_collectives(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(island.last_local_rtt_us(), static_cast<int64_t>(250));
    BOOST_CHECK(island.Collective("c", static_cast<int64_t>(1000), err));
    BOOST_CHECK_EQUAL(island.local_collectives(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(island.last_local_rtt_us(), static_cast<int64_t>(1000));
    BOOST_CHECK(!island.Collective("c", static_cast<int64_t>(1001), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(island.local_collectives(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(island.last_local_rtt_us(), static_cast<int64_t>(1000));
    BOOST_CHECK(!island.launched());
    BOOST_CHECK(!island.broadcast());
    BOOST_CHECK(!island.gpu());
    BOOST_CHECK_EQUAL(island.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(island.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(prefill_and_decode_can_be_two_members)
{
    modelnet::NifIsland island;
    std::string err;
    BOOST_CHECK(island.Admit("alpha", static_cast<int64_t>(40), true, err));
    BOOST_CHECK(island.Admit("beta", static_cast<int64_t>(80), true, err));
    BOOST_CHECK(!island.Place("gamma", "prefill", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(island.Place("alpha", "prefill", err));
    BOOST_CHECK(island.Place("beta", "decode", err));
    BOOST_CHECK_EQUAL(island.placed("prefill"), "alpha");
    BOOST_CHECK_EQUAL(island.placed("decode"), "beta");
    BOOST_CHECK(!island.Place("alpha", "train", err));
    BOOST_CHECK_EQUAL(err, "PHASE");
    BOOST_CHECK_EQUAL(island.placed("prefill"), "alpha");
    BOOST_CHECK_EQUAL(island.placed("decode"), "beta");
    BOOST_CHECK(!island.socket_opened());
    BOOST_CHECK(!island.launched());
    BOOST_CHECK(!island.broadcast());
    BOOST_CHECK(!island.gpu());
    BOOST_CHECK_EQUAL(island.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(island.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(island.local_collectives(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
