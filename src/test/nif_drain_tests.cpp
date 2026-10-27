// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_drain/nif_drain.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_drain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_refusals_store_nothing)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(!drain.Open("", static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(drain.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.deadline_ms(""), static_cast<int64_t>(0));

    BOOST_CHECK(!drain.Open("early", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "DEADLINE");
    BOOST_CHECK(!drain.Open("neg", static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "DEADLINE");
    BOOST_CHECK_EQUAL(drain.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!drain.canceled("early"));
}

BOOST_AUTO_TEST_CASE(replay_open_keeps_first_deadline)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(drain.Open("job", static_cast<int64_t>(7), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(drain.deadline_ms("job"), static_cast<int64_t>(7));
    BOOST_CHECK(!drain.Open("job", static_cast<int64_t>(99), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(drain.deadline_ms("job"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(drain.count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(hold_then_cancel_leaves_bytes)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(!drain.Hold("missing", static_cast<int64_t>(40), err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(drain.Open("job", static_cast<int64_t>(10), err));
    BOOST_CHECK(!drain.Hold("job", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!drain.Hold("job", static_cast<int64_t>(-3), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(drain.Hold("job", static_cast<int64_t>(40), err));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!drain.Cancel("missing", err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(drain.Cancel("job", err));
    BOOST_CHECK(drain.canceled("job"));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!drain.Cancel("job", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(drain.canceled("job"));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(drain.children(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(drain_before_deadline_returns_physical_to_zero)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(drain.Open("job", static_cast<int64_t>(10), err));
    BOOST_CHECK(drain.Hold("job", static_cast<int64_t>(40), err));
    BOOST_CHECK(!drain.Drain("missing", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(!drain.Drain("job", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!drain.drained("job"));

    BOOST_CHECK(drain.Cancel("job", err));
    BOOST_CHECK(drain.Drain("job", static_cast<int64_t>(9), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(drain.drained("job"));
    BOOST_CHECK(drain.drained());
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!drain.Drain("job", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.children(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(drain_at_deadline_is_expired)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(drain.Open("job", static_cast<int64_t>(5), err));
    BOOST_CHECK(drain.Hold("job", static_cast<int64_t>(40), err));
    BOOST_CHECK(drain.Cancel("job", err));
    BOOST_CHECK(!drain.Drain("job", static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!drain.drained("job"));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!drain.Drain("job", static_cast<int64_t>(6), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
}

BOOST_AUTO_TEST_CASE(release_before_drain_is_pinned)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(!drain.Release("missing", err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(drain.Open("job", static_cast<int64_t>(10), err));
    BOOST_CHECK(drain.Hold("job", static_cast<int64_t>(40), err));
    BOOST_CHECK(!drain.Release("job", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));

    BOOST_CHECK(drain.Cancel("job", err));
    BOOST_CHECK(!drain.Release("job", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!drain.drained("job"));

    BOOST_CHECK(drain.Drain("job", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(drain.Release("job", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(overflow_does_not_change_the_total)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(drain.Open("job", static_cast<int64_t>(20), err));
    BOOST_CHECK(drain.Hold("job", static_cast<int64_t>(40), err));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!drain.Hold("job", std::numeric_limits<int64_t>::max(), err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!drain.canceled("job"));
}

BOOST_AUTO_TEST_CASE(idle_flags_stay_false)
{
    modelnet::NifDrain drain;
    std::string err;

    BOOST_CHECK(!drain.launched());
    BOOST_CHECK(!drain.gpu());
    BOOST_CHECK(!drain.broadcast());
    BOOST_CHECK(!drain.qualified());
    BOOST_CHECK(!drain.drained());
    BOOST_CHECK_EQUAL(drain.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(drain.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(drain.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.children(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!modelnet::NifDtEngineLinked("deepinfer"));

    BOOST_CHECK(drain.Open("job", static_cast<int64_t>(10), err));
    BOOST_CHECK(drain.Hold("job", static_cast<int64_t>(40), err));
    BOOST_CHECK(drain.Cancel("job", err));
    BOOST_CHECK(drain.Drain("job", static_cast<int64_t>(4), err));
    BOOST_CHECK(!drain.launched());
    BOOST_CHECK(!drain.gpu());
    BOOST_CHECK(!drain.broadcast());
    BOOST_CHECK(!drain.qualified());
    BOOST_CHECK_EQUAL(drain.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.children(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(drain.physical_bytes(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
