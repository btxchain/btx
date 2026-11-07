// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_parallel/dt_parallel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_parallel_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(plan_two_by_two_is_four_ranks_when_memory_fits)
{
    modelnet::DtParallel plan;
    std::string err;
    BOOST_CHECK(plan.Plan(2, 2, 1, 1, 1, 64, 64, err));
    BOOST_CHECK(plan.feasible());
    BOOST_CHECK_EQUAL(plan.ranks(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(plan.physical_hosts(), 1);
    BOOST_CHECK(!plan.gpu());
    BOOST_CHECK(!plan.launched());
    BOOST_CHECK(!plan.broadcast());
    BOOST_CHECK_EQUAL(plan.automatic_spend(), "0");
    BOOST_CHECK(!plan.Commit(err));
    BOOST_CHECK_EQUAL(err, "PLAN");
    BOOST_CHECK_EQUAL(plan.ranks(), static_cast<int64_t>(4));
    BOOST_CHECK(plan.Freeze(err));
    BOOST_CHECK(plan.Commit(err));
    BOOST_CHECK_EQUAL(plan.ranks(), static_cast<int64_t>(4));
}

BOOST_AUTO_TEST_CASE(memory_over_capacity_and_low_degree_store_nothing)
{
    modelnet::DtParallel over;
    std::string err;
    BOOST_CHECK(!over.Plan(2, 2, 1, 1, 1, 65, 64, err));
    BOOST_CHECK_EQUAL(err, "MEMORY");
    BOOST_CHECK(!over.feasible());
    BOOST_CHECK_EQUAL(over.ranks(), static_cast<int64_t>(0));

    modelnet::DtParallel low;
    BOOST_CHECK(!low.Plan(2, 0, 1, 1, 1, 8, 8, err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK(!low.feasible());
    BOOST_CHECK_EQUAL(low.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK(!low.Freeze(err));
    BOOST_CHECK_EQUAL(err, "PLAN");
    BOOST_CHECK_EQUAL(low.ranks(), static_cast<int64_t>(0));

    modelnet::DtParallel kept;
    BOOST_CHECK(kept.Plan(2, 2, 1, 1, 1, 8, 8, err));
    BOOST_CHECK(!kept.Plan(2, 2, 1, 1, 1, 9, 8, err));
    BOOST_CHECK_EQUAL(err, "MEMORY");
    BOOST_CHECK(kept.feasible());
    BOOST_CHECK_EQUAL(kept.ranks(), static_cast<int64_t>(4));
    BOOST_CHECK(!kept.Plan(0, 2, 1, 1, 1, 8, 8, err));
    BOOST_CHECK_EQUAL(err, "RANK");
    BOOST_CHECK_EQUAL(kept.ranks(), static_cast<int64_t>(4));
}

BOOST_AUTO_TEST_CASE(shrink_after_freeze_does_not_change_ranks)
{
    modelnet::DtParallel plan;
    std::string err;
    BOOST_CHECK(plan.Plan(2, 2, 1, 1, 1, 32, 64, err));
    BOOST_CHECK(!plan.Shrink(1, err));
    BOOST_CHECK_EQUAL(err, "PLAN");
    BOOST_CHECK_EQUAL(plan.ranks(), static_cast<int64_t>(4));
    BOOST_CHECK(plan.Freeze(err));
    BOOST_CHECK(!plan.Plan(1, 1, 1, 1, 1, 32, 64, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK(!plan.Shrink(1, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK(plan.feasible());
    BOOST_CHECK_EQUAL(plan.ranks(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(plan.physical_hosts(), 1);
}

BOOST_AUTO_TEST_CASE(absent_collective_adds_no_ranks)
{
    modelnet::DtParallel empty;
    std::string err;
    BOOST_CHECK(!empty.GpuCollective(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!empty.gpu());
    BOOST_CHECK(!empty.launched());
    BOOST_CHECK(!empty.broadcast());
    BOOST_CHECK_EQUAL(empty.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(empty.ranks(), static_cast<int64_t>(0));

    modelnet::DtParallel plan;
    BOOST_CHECK(plan.Plan(2, 2, 1, 1, 1, 4, 8, err));
    BOOST_CHECK(!plan.GpuCollective(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!plan.gpu());
    BOOST_CHECK(!plan.launched());
    BOOST_CHECK(!plan.broadcast());
    BOOST_CHECK_EQUAL(plan.ranks(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(plan.physical_hosts(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
