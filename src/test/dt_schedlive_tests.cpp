// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_schedlive/dt_schedlive.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

namespace {

void ExpectIdle(const modelnet::DtSchedLive& live)
{
    BOOST_CHECK(!live.launched());
    BOOST_CHECK(!live.gpu());
    BOOST_CHECK(!live.broadcast());
    BOOST_CHECK(!live.qualified());
    BOOST_CHECK(live.monetary_ok());
    BOOST_CHECK(!live.validation_affected());
    BOOST_CHECK_EQUAL(live.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(live.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(live.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(live.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_schedlive_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(schedule_before_reserve_is_order)
{
    modelnet::DtSchedLive live;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!live.scheduled());
    BOOST_CHECK(!live.Schedule(err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SCHEDLIVE_ORDER);
    BOOST_CHECK(!live.scheduled());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!live.Reserve(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK(!live.Schedule(err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK(!live.scheduled());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));
    ExpectIdle(live);
}

BOOST_AUTO_TEST_CASE(reserve_40_schedule_cancel_then_release_to_zero)
{
    modelnet::DtSchedLive live;
    std::string err = "stale";

    BOOST_CHECK(live.Reserve(static_cast<int64_t>(40), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!live.scheduled());
    BOOST_CHECK(!live.canceled());

    BOOST_CHECK(live.Schedule(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(live.scheduled());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));

    BOOST_CHECK(!live.Schedule(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(live.scheduled());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));

    BOOST_CHECK(live.Cancel(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(live.canceled());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));

    BOOST_CHECK(!live.Release(err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SCHEDLIVE_PINNED);
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(live.canceled());

    BOOST_CHECK(live.Quiesce(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));

    BOOST_CHECK(live.Release(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(live.scheduled());
    BOOST_CHECK(live.canceled());
    BOOST_CHECK_EQUAL(live.bytes_moved(), static_cast<int64_t>(0));
    ExpectIdle(live);
}

BOOST_AUTO_TEST_CASE(quiesce_before_cancel_is_order)
{
    modelnet::DtSchedLive live;
    std::string err = "stale";

    BOOST_CHECK(live.Reserve(static_cast<int64_t>(40), err));
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!live.canceled());

    BOOST_CHECK(!live.Quiesce(err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SCHEDLIVE_ORDER);
    BOOST_CHECK(!live.canceled());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));

    BOOST_CHECK(!live.Release(err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));
    ExpectIdle(live);
}

BOOST_AUTO_TEST_CASE(fail_worker_leaves_monetary_ok_and_validation)
{
    modelnet::DtSchedLive live;
    std::string err = "stale";

    BOOST_CHECK(live.Reserve(static_cast<int64_t>(40), err));
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(!live.worker_failed());
    BOOST_CHECK(live.monetary_ok());
    BOOST_CHECK(!live.validation_affected());

    const int64_t physical = live.physical_bytes();
    BOOST_CHECK(live.FailWorker(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(live.worker_failed());
    BOOST_CHECK(live.monetary_ok());
    BOOST_CHECK(!live.validation_affected());
    BOOST_CHECK_EQUAL(live.physical_bytes(), physical);
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(live.bytes_moved(), static_cast<int64_t>(0));
    ExpectIdle(live);
}

BOOST_AUTO_TEST_CASE(spend_leaves_automatic_spend_zero)
{
    modelnet::DtSchedLive live;
    std::string err = "stale";

    BOOST_CHECK(live.Reserve(static_cast<int64_t>(40), err));
    BOOST_CHECK(live.Schedule(err));
    const int64_t physical = live.physical_bytes();
    BOOST_CHECK_EQUAL(physical, static_cast<int64_t>(40));

    BOOST_CHECK(!live.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(live.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(live.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(live.physical_bytes(), physical);
    BOOST_CHECK_EQUAL(live.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(live.monetary_ok());
    BOOST_CHECK(!live.validation_affected());
    BOOST_CHECK(live.scheduled());
    ExpectIdle(live);
}

BOOST_AUTO_TEST_CASE(bytes_and_capacity_store_nothing)
{
    modelnet::DtSchedLive live;
    std::string err = "stale";

    BOOST_CHECK(!live.Reserve(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SCHEDLIVE_BYTES);
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!live.Reserve(static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!live.Reserve(std::numeric_limits<int64_t>::min(), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!live.scheduled());

    BOOST_CHECK(!live.Reserve(static_cast<int64_t>(101), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(err, modelnet::DT_SCHEDLIVE_CAPACITY);
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!live.Reserve(std::numeric_limits<int64_t>::max(), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!live.Schedule(err));
    BOOST_CHECK_EQUAL(err, "ORDER");

    BOOST_CHECK(live.Reserve(static_cast<int64_t>(100), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(100));
    BOOST_CHECK(!live.Reserve(static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(live.physical_bytes(), static_cast<int64_t>(100));

    modelnet::DtSchedLive summed;
    BOOST_CHECK(summed.Reserve(static_cast<int64_t>(40), err));
    BOOST_CHECK(!summed.Reserve(static_cast<int64_t>(61), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(summed.physical_bytes(), static_cast<int64_t>(40));
    BOOST_CHECK(summed.Reserve(static_cast<int64_t>(60), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(summed.physical_bytes(), static_cast<int64_t>(100));
    BOOST_CHECK(!summed.Reserve(std::numeric_limits<int64_t>::max(), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(summed.physical_bytes(), static_cast<int64_t>(100));

    BOOST_CHECK(summed.Cancel(err));
    BOOST_CHECK_EQUAL(summed.physical_bytes(), static_cast<int64_t>(100));
    BOOST_CHECK(summed.Quiesce(err));
    BOOST_CHECK(summed.Release(err));
    BOOST_CHECK_EQUAL(summed.physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(summed.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(summed.hosts(), static_cast<int64_t>(1));
    ExpectIdle(summed);
}

BOOST_AUTO_TEST_SUITE_END()
