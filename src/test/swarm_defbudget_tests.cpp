// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_defbudget/swarm_defbudget.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmDefBudget& budget)
{
    BOOST_CHECK(!budget.launched());
    BOOST_CHECK(!budget.gpu());
    BOOST_CHECK(!budget.broadcast());
    BOOST_CHECK_EQUAL(budget.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(budget.atoms_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_defbudget_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(funding_incident_does_not_fund_readiness)
{
    modelnet::SwarmDefBudget budget;
    std::string err = "prior";

    BOOST_CHECK(!budget.holds_money("incident"));
    BOOST_CHECK(!budget.holds_money("readiness"));
    BOOST_CHECK(!budget.holds_money("improvement"));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.balance("improvement"), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Fund("treasury", "out-i", 10, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!budget.Fund("incident", "out-i", 0, err));
    BOOST_CHECK_EQUAL(err, "AMOUNT");
    BOOST_CHECK(!budget.Fund("incident", "out-i", -3, err));
    BOOST_CHECK_EQUAL(err, "AMOUNT");
    BOOST_CHECK(!budget.Fund("incident", "", 10, err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK(!budget.holds_money("incident"));

    BOOST_REQUIRE(budget.Fund("incident", "out-i", 10, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(budget.holds_money("incident"));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(budget.outpoint("incident"), "out-i");
    BOOST_CHECK(!budget.holds_money("readiness"));
    BOOST_CHECK(!budget.holds_money("improvement"));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.balance("improvement"), static_cast<int64_t>(0));
    BOOST_CHECK(budget.outpoint("readiness").empty());

    BOOST_REQUIRE(budget.Fund("incident", "out-i2", 7, err));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(17));
    BOOST_CHECK_EQUAL(budget.outpoint("incident"), "out-i");
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.holds_money("readiness"));

    BOOST_REQUIRE(budget.Fund("readiness", "out-r", 4, err));
    BOOST_CHECK(budget.holds_money("readiness"));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(17));
    BOOST_CHECK(!budget.holds_money("improvement"));
    BOOST_CHECK_EQUAL(budget.balance("improvement"), static_cast<int64_t>(0));
    ExpectQuiet(budget);
}

BOOST_AUTO_TEST_CASE(same_outpoint_cannot_fund_improvement)
{
    modelnet::SwarmDefBudget budget;
    std::string err = "prior";

    BOOST_REQUIRE(budget.Fund("readiness", "out-shared", 12, err));
    BOOST_CHECK(budget.holds_money("readiness"));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(12));

    BOOST_CHECK(!budget.Fund("improvement", "out-shared", 15, err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK(!budget.holds_money("improvement"));
    BOOST_CHECK_EQUAL(budget.balance("improvement"), static_cast<int64_t>(0));
    BOOST_CHECK(budget.outpoint("improvement").empty());
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(12));
    BOOST_CHECK_EQUAL(budget.outpoint("readiness"), "out-shared");

    BOOST_CHECK(!budget.Fund("incident", "out-shared", 15, err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK(!budget.holds_money("incident"));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Fund("readiness", "out-shared", 12, err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(12));

    BOOST_REQUIRE(budget.Fund("improvement", "out-other", 15, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(budget.holds_money("improvement"));
    BOOST_CHECK_EQUAL(budget.balance("improvement"), static_cast<int64_t>(15));
    BOOST_CHECK_EQUAL(budget.outpoint("improvement"), "out-other");
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(12));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(0));
    ExpectQuiet(budget);
}

BOOST_AUTO_TEST_CASE(join_does_not_earn)
{
    modelnet::SwarmDefBudget budget;
    std::string err = "prior";

    BOOST_CHECK(!budget.Join("treasury", "alice", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!budget.member_of("treasury", "alice"));

    BOOST_CHECK(!budget.Join("incident", "", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(!budget.member_of("incident", ""));

    BOOST_CHECK(!budget.Join("incident", "alice", err));
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
    BOOST_CHECK(budget.member_of("incident", "alice"));
    BOOST_CHECK(!budget.member_of("readiness", "alice"));
    BOOST_CHECK(!budget.member_of("improvement", "alice"));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.earned("alice"));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.holds_money("incident"));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Join("incident", "alice", err));
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Join("readiness", "bob", err));
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
    BOOST_CHECK(budget.member_of("readiness", "bob"));
    BOOST_CHECK(!budget.member_of("incident", "bob"));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.earned_atoms("readiness"), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Earn("incident", "work-1", "alice", 5, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(!budget.earned("work-1"));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK(budget.member_of("incident", "alice"));

    BOOST_REQUIRE(budget.Fund("incident", "out-i", 20, err));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(20));
    BOOST_CHECK(budget.member_of("incident", "alice"));
    BOOST_CHECK(!budget.holds_money("readiness"));
    ExpectQuiet(budget);
}

BOOST_AUTO_TEST_CASE(second_receipt_is_duplicate)
{
    modelnet::SwarmDefBudget budget;
    std::string err = "prior";

    BOOST_CHECK(!budget.Earn("treasury", "work-1", "alice", 4, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!budget.Earn("incident", "work-1", "alice", 0, err));
    BOOST_CHECK_EQUAL(err, "AMOUNT");
    BOOST_CHECK(!budget.Earn("readiness", "work-1", "alice", 1, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));

    BOOST_REQUIRE(budget.Fund("incident", "out-i", 100, err));
    BOOST_REQUIRE(budget.Fund("improvement", "out-p", 80, err));
    BOOST_CHECK(!budget.holds_money("readiness"));

    BOOST_REQUIRE(budget.Earn("incident", "work-1", "alice", 4, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(budget.earned("work-1"));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(100));

    BOOST_CHECK(!budget.Earn("improvement", "work-1", "bob", 4, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(budget.earned_atoms("improvement"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(1));

    BOOST_REQUIRE(budget.Earn("incident", "work-2", "receipt-a", "alice", 6, err));
    BOOST_CHECK(budget.earned("work-2"));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(100));

    BOOST_CHECK(!budget.Earn("incident", "work-9", "receipt-a", "alice", 1, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK(!budget.earned("work-9"));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(2));

    BOOST_CHECK(!budget.Earn("improvement", "work-3", "receipt-a", "bob", 7, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    BOOST_CHECK(!budget.earned("work-3"));
    BOOST_CHECK_EQUAL(budget.earned_atoms("improvement"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.balance("improvement"), static_cast<int64_t>(80));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(2));

    BOOST_REQUIRE(budget.Earn("improvement", "work-3", "receipt-b", "bob", 7, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(budget.earned("work-3"));
    BOOST_CHECK_EQUAL(budget.earned_atoms("improvement"), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(budget.balance("improvement"), static_cast<int64_t>(80));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(0));
    ExpectQuiet(budget);
}

BOOST_AUTO_TEST_CASE(milestone_above_the_cap_pays_nothing)
{
    modelnet::SwarmDefBudget budget;
    std::string err = "prior";

    BOOST_REQUIRE(budget.Fund("incident", "out-i", 50, err));
    BOOST_REQUIRE(budget.Fund("readiness", "out-r", 50, err));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Milestone("treasury", "ms-1", 10, 10, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!budget.Milestone("incident", "ms-1", 40, 30, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!budget.milestone_stored("ms-1"));
    BOOST_CHECK_EQUAL(budget.milestone_paid("ms-1"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(50));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(50));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.atoms_moved(), static_cast<int64_t>(0));

    BOOST_REQUIRE(budget.Milestone("incident", "ms-1", 30, 30, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(budget.milestone_stored("ms-1"));
    BOOST_CHECK_EQUAL(budget.milestone_paid("ms-1"), static_cast<int64_t>(30));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(50));
    BOOST_CHECK(budget.holds_money("incident"));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));

    BOOST_REQUIRE(budget.Milestone("readiness", "ms-low", 10, 40, err));
    BOOST_CHECK(budget.milestone_stored("ms-low"));
    BOOST_CHECK_EQUAL(budget.milestone_paid("ms-low"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(20));

    BOOST_CHECK(!budget.Milestone("incident", "ms-2", 25, 25, err));
    BOOST_CHECK_EQUAL(err, "NEGATIVE");
    BOOST_CHECK(!budget.milestone_stored("ms-2"));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.Milestone("improvement", "ms-u", 1, 1, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(!budget.milestone_stored("ms-u"));
    BOOST_CHECK(!budget.holds_money("improvement"));

    modelnet::SwarmDefBudget exact;
    BOOST_REQUIRE(exact.Fund("improvement", "out-e", 5, err));
    BOOST_REQUIRE(exact.Milestone("improvement", "ms-eq", 5, 5, err));
    BOOST_CHECK(exact.milestone_stored("ms-eq"));
    BOOST_CHECK_EQUAL(exact.milestone_paid("ms-eq"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(exact.balance("improvement"), static_cast<int64_t>(0));
    BOOST_CHECK(exact.holds_money("improvement"));
    BOOST_CHECK(!exact.holds_money("readiness"));
    BOOST_CHECK(!exact.Milestone("improvement", "ms-more", 1, 1, err));
    BOOST_CHECK_EQUAL(err, "NEGATIVE");
    BOOST_CHECK(!exact.milestone_stored("ms-more"));
    BOOST_CHECK_EQUAL(exact.balance("improvement"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(exact.atoms_moved(), static_cast<int64_t>(0));
    ExpectQuiet(budget);
    ExpectQuiet(exact);
}

BOOST_AUTO_TEST_CASE(automatic_spend_is_zero)
{
    modelnet::SwarmDefBudget budget;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(budget.automatic_spend(), "0");

    BOOST_REQUIRE(budget.SetPayer("payer-1", err));
    BOOST_CHECK(!budget.SelfDeal("payer-1", err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_REQUIRE(budget.SelfDeal("worker-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.payer(), "payer-1");

    BOOST_REQUIRE(budget.Fund("incident", "out-i", 30, err));
    BOOST_CHECK(!budget.Join("incident", "worker-1", err));
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
    BOOST_REQUIRE(budget.Earn("incident", "work-1", "receipt-1", "worker-1", 3, err));
    BOOST_REQUIRE(budget.Milestone("incident", "ms-1", 12, 12, err));

    BOOST_CHECK_EQUAL(budget.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(budget.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.broadcast());
    BOOST_CHECK(!budget.launched());
    BOOST_CHECK(!budget.gpu());
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(18));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(budget.balance("readiness"), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.holds_money("readiness"));
    ExpectQuiet(budget);
}

BOOST_AUTO_TEST_CASE(self_deal_stores_no_earned_row)
{
    modelnet::SwarmDefBudget budget;
    std::string err = "prior";

    BOOST_CHECK(!budget.SelfDeal("alice", err));
    BOOST_CHECK_EQUAL(err, "PAYER");
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!budget.SetPayer("", err));
    BOOST_CHECK_EQUAL(err, "PAYER");
    BOOST_CHECK(budget.payer().empty());

    BOOST_REQUIRE(budget.SetPayer("alice", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.payer(), "alice");
    BOOST_CHECK(!budget.SetPayer("bob", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(budget.payer(), "alice");

    BOOST_CHECK(!budget.SelfDeal("", err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(!budget.SelfDeal("alice", err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.earned_atoms("incident"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(budget.balance("incident"), static_cast<int64_t>(0));

    BOOST_REQUIRE(budget.SelfDeal("bob", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!budget.holds_money("readiness"));
    BOOST_CHECK(!budget.holds_money("incident"));
    BOOST_CHECK(!budget.holds_money("improvement"));
    ExpectQuiet(budget);
}

BOOST_AUTO_TEST_SUITE_END()
