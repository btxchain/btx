// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_budget/dt_budget.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_budget_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cancel_keeps_physical_until_quiesce_and_release)
{
    modelnet::DtBudget budget;
    std::string err = "stale";
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.canceled());

    BOOST_CHECK(budget.Reserve("job", static_cast<int64_t>(40), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(40));

    BOOST_CHECK(budget.Schedule("job", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(40));

    BOOST_CHECK(!budget.Schedule("missing", err));
    BOOST_CHECK_EQUAL(err, "RESERVE");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(40));

    BOOST_CHECK(budget.Cancel("job", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(budget.canceled());
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(40));

    BOOST_CHECK(!budget.Release("job", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(40));
    BOOST_CHECK(budget.canceled());

    BOOST_CHECK(budget.Quiesce("job", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(40));

    BOOST_CHECK(budget.Release("job", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.canceled());

    BOOST_CHECK(!budget.launched());
    BOOST_CHECK(!budget.gpu());
    BOOST_CHECK(!budget.broadcast());
    BOOST_CHECK_EQUAL(budget.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(budget.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(oversize_reserve_stores_nothing)
{
    modelnet::DtBudget budget;
    std::string err = "stale";
    BOOST_CHECK(!budget.Reserve("over", static_cast<int64_t>(101), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.canceled());
    BOOST_CHECK(!budget.Schedule("over", err));
    BOOST_CHECK_EQUAL(err, "RESERVE");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Reserve("", static_cast<int64_t>(40), err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Reserve("zero", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.Reserve("neg", static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(duplicate_and_remainder_leave_the_first_lease)
{
    modelnet::DtBudget budget;
    std::string err = "stale";
    BOOST_CHECK(budget.Reserve("a", static_cast<int64_t>(40), err));
    BOOST_CHECK(!budget.Reserve("a", static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(40));

    BOOST_CHECK(budget.Reserve("b", static_cast<int64_t>(25), err));
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(65));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(65));
    BOOST_CHECK(!budget.Reserve("c", static_cast<int64_t>(61), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(65));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(65));

    BOOST_CHECK(budget.Cancel("a", err));
    BOOST_CHECK(budget.canceled());
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(65));
    BOOST_CHECK(!budget.Release("a", err));
    BOOST_CHECK_EQUAL(err, "PINNED");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(65));

    BOOST_CHECK(budget.Quiesce("a", err));
    BOOST_CHECK(budget.Release("a", err));
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(25));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(25));
    BOOST_CHECK(!budget.canceled());
    BOOST_CHECK(budget.Schedule("b", err));
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(25));

    BOOST_CHECK(!budget.Reserve("over", static_cast<int64_t>(101), err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(25));

    BOOST_CHECK(budget.Quiesce("b", err));
    BOOST_CHECK(budget.Release("b", err));
    BOOST_CHECK_EQUAL(budget.physical(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.reserved(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.launched());
    BOOST_CHECK(!budget.gpu());
    BOOST_CHECK(!budget.broadcast());
    BOOST_CHECK_EQUAL(budget.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
