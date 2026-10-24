// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_delay/dt_delay.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_delay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(base_a_deltas_three_and_four_resume_moves_head_by_seven)
{
    modelnet::DtDelay delay;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.has_base());
    BOOST_CHECK(delay.base().empty());
    BOOST_CHECK(!delay.launched());
    BOOST_CHECK(!delay.gpu());
    BOOST_CHECK(!delay.broadcast());
    BOOST_CHECK(!delay.diloco_complete());
    BOOST_CHECK_EQUAL(delay.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(delay.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(delay.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(delay.Base("a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(delay.has_base());
    BOOST_CHECK_EQUAL(delay.base(), "a");

    BOOST_CHECK(delay.Delay(static_cast<int64_t>(3), static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));

    BOOST_CHECK(delay.Delay(static_cast<int64_t>(4), static_cast<int64_t>(2), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));

    const int64_t head_before = delay.head();
    BOOST_CHECK(delay.Resume("a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(delay.head() - head_before, static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!delay.Wan(err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.launched());
    BOOST_CHECK(!delay.gpu());
    BOOST_CHECK(!delay.broadcast());
    BOOST_CHECK(!delay.diloco_complete());
    BOOST_CHECK_EQUAL(delay.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(delay.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(lag_three_does_not_add)
{
    modelnet::DtDelay delay;
    std::string err = "prior";
    BOOST_CHECK(delay.Base("a", err));
    BOOST_CHECK(delay.Delay(static_cast<int64_t>(3), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(3));

    BOOST_CHECK(!delay.Delay(static_cast<int64_t>(4), static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_STALE);
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(delay.Resume("a", err));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.launched());
    BOOST_CHECK(!delay.gpu());
    BOOST_CHECK(!delay.broadcast());
}

BOOST_AUTO_TEST_CASE(resume_b_is_change_and_leaves_the_head)
{
    modelnet::DtDelay delay;
    std::string err = "prior";
    BOOST_CHECK(delay.Base("a", err));
    BOOST_CHECK(delay.Delay(static_cast<int64_t>(3), static_cast<int64_t>(2), err));
    BOOST_CHECK(delay.Delay(static_cast<int64_t>(4), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));

    BOOST_CHECK(!delay.Resume("b", err));
    BOOST_CHECK_EQUAL(err, "CHANGE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_CHANGE);
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.base(), "a");

    BOOST_CHECK(delay.Resume("a", err));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));

    const int64_t head_at = delay.head();
    BOOST_CHECK(!delay.Resume("b", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_CHANGE);
    BOOST_CHECK_EQUAL(delay.head(), head_at);
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.diloco_complete());
    BOOST_CHECK_EQUAL(delay.physical_hosts(), 1);
}

BOOST_AUTO_TEST_CASE(wan_moves_zero_bytes)
{
    modelnet::DtDelay delay;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.Wan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.launched());
    BOOST_CHECK(!delay.gpu());
    BOOST_CHECK(!delay.broadcast());
    BOOST_CHECK(!delay.diloco_complete());
    BOOST_CHECK_EQUAL(delay.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(delay.physical_hosts(), 1);
}

BOOST_AUTO_TEST_CASE(empty_base_change_and_replay_keep_the_first)
{
    modelnet::DtDelay delay;
    std::string err = "prior";
    BOOST_CHECK(!delay.Base("", err));
    BOOST_CHECK_EQUAL(err, "BASE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_BASE);
    BOOST_CHECK(!delay.has_base());
    BOOST_CHECK(delay.base().empty());
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));

    BOOST_CHECK(delay.Base("a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!delay.Base("b", err));
    BOOST_CHECK_EQUAL(err, "CHANGE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_CHANGE);
    BOOST_CHECK_EQUAL(delay.base(), "a");
    BOOST_CHECK(delay.has_base());

    BOOST_CHECK(!delay.Base("a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(delay.base(), "a");
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!delay.Base("", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_BASE);
    BOOST_CHECK_EQUAL(delay.base(), "a");
}

BOOST_AUTO_TEST_CASE(second_resume_with_pending_zero_is_unchanged)
{
    modelnet::DtDelay delay;
    std::string err = "prior";
    BOOST_CHECK(delay.Base("a", err));
    BOOST_CHECK(delay.Delay(static_cast<int64_t>(3), static_cast<int64_t>(2), err));
    BOOST_CHECK(delay.Delay(static_cast<int64_t>(4), static_cast<int64_t>(2), err));
    BOOST_CHECK(delay.Resume("a", err));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));

    BOOST_CHECK(!delay.Resume("a", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_UNCHANGED);
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.launched());
    BOOST_CHECK(!delay.gpu());
    BOOST_CHECK(!delay.broadcast());
    BOOST_CHECK(!delay.diloco_complete());
    BOOST_CHECK_EQUAL(delay.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(delay.physical_hosts(), 1);

    BOOST_CHECK(delay.Delay(static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(7));
    BOOST_CHECK(delay.Resume("a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.Resume("a", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_UNCHANGED);
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(8));
}

BOOST_AUTO_TEST_CASE(sum_that_does_not_fit_is_overflow)
{
    modelnet::DtDelay delay;
    std::string err = "prior";
    BOOST_CHECK(delay.Base("a", err));
    BOOST_CHECK(delay.Delay(std::numeric_limits<int64_t>::max(), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(delay.pending(), std::numeric_limits<int64_t>::max());
    BOOST_CHECK(!delay.Delay(static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_OVERFLOW);
    BOOST_CHECK_EQUAL(delay.pending(), std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(delay.head(), static_cast<int64_t>(0));

    BOOST_CHECK(delay.Resume("a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(delay.head(), std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(0));

    BOOST_CHECK(delay.Delay(static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(1));
    BOOST_CHECK(!delay.Resume("a", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_DELAY_OVERFLOW);
    BOOST_CHECK_EQUAL(delay.head(), std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(delay.pending(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(delay.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!delay.launched());
    BOOST_CHECK(!delay.gpu());
    BOOST_CHECK(!delay.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
