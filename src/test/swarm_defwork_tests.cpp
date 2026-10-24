// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_defwork/swarm_defwork.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmDefWork& work)
{
    BOOST_CHECK(!work.launched());
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK(!work.broadcast());
    BOOST_CHECK(!work.connected());
    BOOST_CHECK_EQUAL(work.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(work.atoms_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_AUTO_TEST_SUITE(swarm_defwork_tests)

BOOST_FIXTURE_TEST_CASE(d3_without_a_human_stays_unapproved, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_CHECK(!work.Propose("case-1", "action-d3", "D3", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "NEED_APPROVAL");
    BOOST_CHECK(work.proposed("action-d3"));
    BOOST_CHECK_EQUAL(work.level_of("action-d3"), "D3");
    BOOST_CHECK(!work.approved("action-d3"));

    BOOST_CHECK(!work.Approve("case-1", "action-d3", false, err));
    BOOST_CHECK_EQUAL(err, "NEED_APPROVAL");
    BOOST_CHECK(!work.approved("action-d3"));
    BOOST_CHECK(!work.Execute("case-1", "action-d3", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "NEED_APPROVAL");
    BOOST_CHECK(!work.has_receipt("action-d3"));
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(0));

    BOOST_CHECK(!work.Approve("case-1", "missing", false, err));
    BOOST_CHECK_EQUAL(err, "NEED_APPROVAL");
    BOOST_CHECK(!work.proposed("missing"));
    BOOST_CHECK(!work.Approve("case-1", "missing", true, err));
    BOOST_CHECK_EQUAL(err, "ACTION");
    BOOST_CHECK(!work.approved("action-d3"));
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(d4_is_refused, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_CHECK(!work.Propose("case-1", "action-d4", "D4", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "REFUSED");
    BOOST_CHECK(!work.proposed("action-d4"));
    BOOST_CHECK(work.asset_of("action-d4").empty());
    BOOST_CHECK(work.level_of("action-d4").empty());
    BOOST_CHECK(!work.Execute("case-1", "action-d4", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "ACTION");
    BOOST_CHECK(!work.has_receipt("action-d4"));
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(0));
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(mismatched_asset_does_not_execute, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_REQUIRE(work.Propose("case-1", "action-1", "D1", "asset-1", 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!work.Execute("case-1", "action-1", "asset-2", 2, err));
    BOOST_CHECK_EQUAL(err, "PRECONDITION");
    BOOST_CHECK(!work.has_receipt("action-1"));
    BOOST_CHECK_EQUAL(work.asset_of("action-1"), "asset-1");
    BOOST_CHECK_EQUAL(work.blast_of("action-1"), static_cast<int64_t>(2));

    BOOST_CHECK(!work.Execute("case-1", "action-1", "asset-1", 3, err));
    BOOST_CHECK_EQUAL(err, "PRECONDITION");
    BOOST_CHECK(!work.Execute("case-2", "action-1", "asset-1", 2, err));
    BOOST_CHECK_EQUAL(err, "PRECONDITION");
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(0));

    BOOST_REQUIRE(work.Execute("case-1", "action-1", "asset-1", 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(work.has_receipt("action-1"));
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!work.Execute("case-1", "action-1", "asset-1", 2, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(work.asset_of("action-1"), "asset-1");
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(unknown_then_execute_stays_ambiguous, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_REQUIRE(work.Propose("case-1", "action-1", "D2", "asset-1", 1, err));
    BOOST_CHECK(!work.Unknown("action-1", err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK(work.ambiguous("action-1"));
    BOOST_CHECK(!work.Execute("case-1", "action-1", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK(!work.has_receipt("action-1"));
    BOOST_CHECK(!work.Execute("case-1", "action-1", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(work.asset_of("action-1"), "asset-1");

    BOOST_CHECK(!work.Unknown("action-external", err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK(!work.proposed("action-external"));
    BOOST_CHECK(!work.Execute("case-1", "action-external", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "AMBIGUOUS");
    BOOST_CHECK(!work.has_receipt("action-external"));
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(retaliate_is_out_of_scope, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_REQUIRE(work.Propose("case-1", "action-1", "D0", "asset-1", 1, err));
    BOOST_CHECK(!work.Retaliate("outside", err));
    BOOST_CHECK_EQUAL(err, "OUT_OF_SCOPE");
    BOOST_CHECK(!work.Retaliate("", err));
    BOOST_CHECK_EQUAL(err, "OUT_OF_SCOPE");
    BOOST_CHECK(work.proposed("action-1"));
    BOOST_CHECK(!work.proposed("outside"));
    BOOST_CHECK(!work.proposed(""));
    BOOST_CHECK(!work.ambiguous("outside"));
    BOOST_CHECK_EQUAL(work.asset_of("action-1"), "asset-1");
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(0));
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(spend_stays_zero, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";
    ExpectQuiet(work);

    BOOST_REQUIRE(work.Propose("case-1", "action-1", "D0", "asset-1", 1, err));
    BOOST_REQUIRE(work.Execute("case-1", "action-1", "asset-1", 1, err));
    BOOST_CHECK(work.has_receipt("action-1"));
    BOOST_CHECK(!work.launched());
    BOOST_CHECK_EQUAL(work.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(work.atoms_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!work.Rollback("action-1", false, err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK(!work.Retaliate("outside", err));
    BOOST_CHECK_EQUAL(work.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(work.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!work.gpu());
    BOOST_CHECK(!work.broadcast());
    BOOST_CHECK(!work.connected());
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(human_approval_records_one_receipt, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_CHECK(!work.Propose("case-1", "action-d3", "D3", "asset-1", 4, err));
    BOOST_CHECK_EQUAL(err, "NEED_APPROVAL");
    BOOST_CHECK(!work.Approve("other-case", "action-d3", true, err));
    BOOST_CHECK_EQUAL(err, "ACTION");
    BOOST_CHECK(!work.approved("action-d3"));

    BOOST_REQUIRE(work.Approve("case-1", "action-d3", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(work.approved("action-d3"));
    BOOST_CHECK(work.Approve("case-1", "action-d3", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(work.approved("action-d3"));

    BOOST_REQUIRE(work.Execute("case-1", "action-d3", "asset-1", 4, err));
    BOOST_CHECK(work.has_receipt("action-d3"));
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!work.Execute("case-1", "action-d3", "asset-1", 4, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(1));
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(preauthorized_approve_is_replay, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_REQUIRE(work.Propose("case-1", "action-d0", "D0", "asset-1", 0, err));
    BOOST_REQUIRE(work.Propose("case-1", "action-d1", "D1", "asset-1", 1, err));
    BOOST_REQUIRE(work.Propose("case-1", "action-d2", "D2", "asset-1", 1, err));
    BOOST_CHECK(work.Approve("case-1", "action-d0", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!work.approved("action-d0"));
    BOOST_CHECK(work.Approve("case-1", "action-d2", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!work.approved("action-d2"));

    BOOST_REQUIRE(work.Execute("case-1", "action-d0", "asset-1", 0, err));
    BOOST_REQUIRE(work.Execute("case-1", "action-d1", "asset-1", 1, err));
    BOOST_REQUIRE(work.Execute("case-1", "action-d2", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(3));
    BOOST_CHECK(!work.Execute("case-1", "action-d1", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(3));
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(rollback_does_not_widen_the_asset, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_CHECK(!work.Rollback("missing", false, err));
    BOOST_CHECK_EQUAL(err, "ACTION");
    BOOST_CHECK(!work.rolled_back("missing"));
    BOOST_CHECK(!work.proposed("missing"));

    BOOST_REQUIRE(work.Propose("case-1", "action-hold", "D2", "asset-1", 1, err));
    BOOST_CHECK(!work.Rollback("action-hold", false, err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK(work.rolled_back("action-hold"));
    BOOST_CHECK_EQUAL(work.asset_of("action-hold"), "asset-1");
    BOOST_CHECK_EQUAL(work.blast_of("action-hold"), static_cast<int64_t>(1));
    BOOST_CHECK(!work.Execute("case-1", "action-hold", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK(!work.has_receipt("action-hold"));
    BOOST_CHECK(!work.Rollback("action-hold", true, err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(work.asset_of("action-hold"), "asset-1");

    BOOST_REQUIRE(work.Propose("case-1", "action-done", "D0", "asset-1", 1, err));
    BOOST_REQUIRE(work.Rollback("action-done", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!work.rolled_back("action-done"));
    BOOST_REQUIRE(work.Execute("case-1", "action-done", "asset-1", 1, err));
    BOOST_CHECK(!work.Rollback("action-done", false, err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK(work.rolled_back("action-done"));
    BOOST_CHECK(work.has_receipt("action-done"));
    BOOST_CHECK_EQUAL(work.asset_of("action-done"), "asset-1");
    BOOST_CHECK_EQUAL(work.receipt_count(), static_cast<int64_t>(1));
    ExpectQuiet(work);
}

BOOST_FIXTURE_TEST_CASE(rejected_proposal_stores_nothing, BasicTestingSetup)
{
    modelnet::SwarmDefWork work;
    std::string err = "prior";

    BOOST_CHECK(!work.Propose("", "action-1", "D0", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "ACTION");
    BOOST_CHECK(!work.Propose("case-1", "", "D0", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "ACTION");
    BOOST_CHECK(!work.Propose("case-1", "action-1", "D0", "", 1, err));
    BOOST_CHECK_EQUAL(err, "ACTION");
    BOOST_CHECK(!work.Propose("case-1", "action-1", "D0", "asset-1", -1, err));
    BOOST_CHECK_EQUAL(err, "BLAST");
    BOOST_CHECK(!work.Propose("case-1", "action-1", "D5", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "LEVEL");
    BOOST_CHECK(!work.Propose("case-1", "action-1", "", "asset-1", 1, err));
    BOOST_CHECK_EQUAL(err, "LEVEL");
    BOOST_CHECK(!work.proposed("action-1"));

    BOOST_REQUIRE(work.Propose("case-1", "action-1", "D2", "asset-1", 2, err));
    BOOST_CHECK(!work.Propose("case-1", "action-1", "D0", "asset-wider", 9, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!work.Propose("case-1", "action-1", "D4", "asset-wider", 9, err));
    BOOST_CHECK_EQUAL(err, "REFUSED");
    BOOST_CHECK_EQUAL(work.level_of("action-1"), "D2");
    BOOST_CHECK_EQUAL(work.asset_of("action-1"), "asset-1");
    BOOST_CHECK_EQUAL(work.blast_of("action-1"), static_cast<int64_t>(2));
    ExpectQuiet(work);
}

BOOST_AUTO_TEST_SUITE_END()
