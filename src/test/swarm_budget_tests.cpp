// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bound/swarm_bound.h>
#include <modelnet/swarm_budget.h>
#include <modelnet/swarm_close.h>
#include <modelnet/swarm_economy.h>
#include <modelnet/swarm_evalboard/board.h>
#include <modelnet/swarm_evolution.h>
#include <modelnet/swarm_execution.h>
#include <modelnet/swarm_fabric.h>
#include <modelnet/swarm_fiatquote.h>
#include <modelnet/swarm_frontier.h>
#include <modelnet/swarm_hashlock.h>
#include <modelnet/swarm_hashlock/hashlock.h>
#include <modelnet/swarm_kvpage.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_prefetch.h>
#include <modelnet/swarm_presence.h>
#include <modelnet/swarm_profit.h>
#include <modelnet/swarm_profitshare.h>
#include <modelnet/swarm_receipt.h>
#include <modelnet/swarm_receiptbook.h>
#include <modelnet/swarm_records.h>
#include <modelnet/swarm_revsplit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <type_traits>

BOOST_FIXTURE_TEST_SUITE(swarm_budget_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_spend_exhaust_leaves_remainder)
{
    modelnet::SwarmResearchBudget budget;
    std::string err = "stale";

    BOOST_CHECK(!budget.Open("", 4, err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_CHECK_EQUAL(budget.Remaining(""), -1);

    BOOST_CHECK(!budget.Open("alpha", 0, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), -1);

    BOOST_CHECK(!budget.Open("alpha", -3, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), -1);

    BOOST_REQUIRE(budget.Open("alpha", 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 5);

    BOOST_CHECK(!budget.Open("alpha", 9, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 5);

    BOOST_CHECK(!budget.Spend("missing", 1, err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_CHECK_EQUAL(budget.Remaining("missing"), -1);
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 5);

    BOOST_CHECK(!budget.Spend("alpha", 0, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 5);

    BOOST_REQUIRE(budget.Spend("alpha", 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 3);

    BOOST_CHECK(!budget.Spend("alpha", 4, err));
    BOOST_CHECK_EQUAL(err, "EXHAUSTED");
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 3);

    BOOST_REQUIRE(budget.Spend("alpha", 3, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 0);

    BOOST_CHECK(!budget.Spend("alpha", 1, err));
    BOOST_CHECK_EQUAL(err, "EXHAUSTED");
    BOOST_CHECK_EQUAL(budget.Remaining("alpha"), 0);
}

BOOST_AUTO_TEST_CASE(research_budget_and_governor_can_coexist)
{
    // Including both headers also prevents the former incompatible
    // modelnet::SwarmBudget definitions from silently colliding at link time.
    modelnet::SwarmResearchBudget research;
    std::string err;
    BOOST_REQUIRE(research.Open("coexistence", 2, err));
    modelnet::SwarmDevice device;
    device.idle_contribution = true;
    device.slots = 1;
    {
        const modelnet::SwarmBudget governed = modelnet::SwarmGovern(device, 1);
        BOOST_CHECK_EQUAL(governed.code, "ADMITTED");
        BOOST_CHECK_EQUAL(governed.active_workers, 1);
        BOOST_REQUIRE(research.Spend("coexistence", 1, err));
        BOOST_CHECK_EQUAL(research.Remaining("coexistence"), 1);
    }
    const modelnet::SwarmBudget drained = modelnet::SwarmGovern(device, 0);
    BOOST_CHECK_EQUAL(drained.code, "NO_SLOTS");
    BOOST_CHECK(drained.drained);
    BOOST_CHECK_EQUAL(research.Remaining("coexistence"), 1);
}

BOOST_AUTO_TEST_CASE(public_swarm_types_and_request_types_can_coexist)
{
    // These header pairs formerly declared incompatible classes with identical
    // fully qualified names. Their inline special members could collide in the
    // full binary. Keep both definitions visible and exercise their lifetimes.
    static_assert(!std::is_same_v<modelnet::SwarmBound, modelnet::SwarmBoundProbe>);
    static_assert(!std::is_same_v<modelnet::SwarmEvalBoard, modelnet::SwarmEvalProbeBoard>);
    static_assert(!std::is_same_v<modelnet::SwarmFiatQuote, modelnet::SwarmFiatQuoteRequest>);
    static_assert(!std::is_same_v<modelnet::SwarmHashlock, modelnet::SwarmHashlockRequest>);
    static_assert(!std::is_same_v<modelnet::SwarmKvPage, modelnet::SwarmKvPageRegistry>);
    static_assert(!std::is_same_v<modelnet::SwarmPrefetch, modelnet::SwarmPrefetchRequest>);
    static_assert(!std::is_same_v<modelnet::SwarmPresence, modelnet::SwarmLocalPresenceRequest>);
    static_assert(!std::is_same_v<modelnet::SwarmProfitShare, modelnet::SwarmProfitShareRequest>);
    static_assert(!std::is_same_v<modelnet::SwarmProfitShareResult, modelnet::SwarmProfitShareRefusal>);
    static_assert(!std::is_same_v<modelnet::SwarmReceiptBook, modelnet::SwarmReceiptRequest>);
    static_assert(!std::is_same_v<modelnet::SwarmRevenueSplit, modelnet::SwarmRevenueSplitRequest>);
    const std::string marker(80, 'x'); // Exercise heap-owned strings, not just small-string storage.
    {
        modelnet::SwarmBound result;
        modelnet::SwarmBoundProbe probe;
        result.method = marker;
        BOOST_CHECK_EQUAL(probe.ticks(), 0);
        BOOST_CHECK(!probe.release_qualified());
        BOOST_CHECK_EQUAL(result.method, marker);
    }
    {
        modelnet::SwarmEvalBoard board;
        modelnet::SwarmEvalProbeBoard probe;
        modelnet::SwarmEvalResult result;
        result.candidate_id = marker;
        result.pool_id = "coexistence";
        board.Append(result);
        BOOST_CHECK(!probe.accepted(marker));
        const auto rows = board.ForPool("coexistence");
        BOOST_REQUIRE_EQUAL(rows.size(), 1U);
        BOOST_CHECK_EQUAL(rows[0].candidate_id, marker);
    }
    {
        modelnet::SwarmFiatQuote quote;
        modelnet::SwarmFiatQuoteRequest request;
        quote.usd = marker;
        quote.btx_atoms = "0";
        request.quote_id = "request";
        request.currency = marker;
        BOOST_CHECK_EQUAL(quote.usd, request.currency);
        BOOST_CHECK(!quote.converted);
        BOOST_CHECK(!request.want_balance);
    }
    {
        modelnet::SwarmHashlock ledger;
        modelnet::SwarmHashlockRequest request;
        request.invoice_id = marker;
        BOOST_CHECK(!ledger.offered(marker));
        BOOST_CHECK(!request.want_qualify);
        BOOST_CHECK_EQUAL(request.invoice_id, marker);
    }
    {
        modelnet::SwarmKvPage page;
        modelnet::SwarmKvPageRegistry registry;
        page.fingerprint = marker;
        BOOST_CHECK(!registry.shared(marker));
        BOOST_CHECK(page.finite);
        BOOST_CHECK_EQUAL(page.fingerprint, marker);
    }
    {
        modelnet::SwarmPrefetch result;
        modelnet::SwarmPrefetchRequest request{};
        result.code = marker;
        request.page_id = marker;
        BOOST_CHECK(!result.bytes_moved);
        BOOST_CHECK(!request.want_prefetch);
        BOOST_CHECK_EQUAL(result.code, request.page_id);
    }
    {
        modelnet::SwarmPresence record;
        modelnet::SwarmLocalPresenceRequest request{};
        record.peer_id = marker;
        record.capabilities.push_back("coexistence");
        request.node_id = marker;
        BOOST_REQUIRE_EQUAL(record.capabilities.size(), 1U);
        BOOST_CHECK(!request.want_connect);
        BOOST_CHECK_EQUAL(record.peer_id, request.node_id);
    }
    {
        modelnet::SwarmProfitShare share;
        modelnet::SwarmProfitShareRequest request{};
        modelnet::SwarmProfitShareResult result;
        modelnet::SwarmProfitShareRefusal refusal{};
        share.instrument_id = marker;
        request.share_id = marker;
        result.code = "production-" + marker;
        refusal.code = "request-" + marker;
        BOOST_CHECK_EQUAL(share.instrument_id, request.share_id);
        BOOST_CHECK(!result.accepted);
        BOOST_CHECK(!refusal.shared);
        BOOST_CHECK_EQUAL(result.code, "production-" + marker);
        BOOST_CHECK_EQUAL(refusal.code, "request-" + marker);
    }
    {
        modelnet::SwarmReceiptBook book;
        modelnet::SwarmReceiptRequest request;
        request.receipt_id = marker;
        BOOST_CHECK_EQUAL(book.Count(), 0);
        BOOST_CHECK(!request.want_book);
        BOOST_CHECK_EQUAL(request.receipt_id, marker);
    }
    {
        modelnet::SwarmRevenueSplit result;
        modelnet::SwarmRevenueSplitRequest request;
        result.compute_atoms = 3;
        request.pool_id = marker;
        request.gross = 7;
        BOOST_CHECK_EQUAL(result.compute_atoms, 3);
        BOOST_CHECK_EQUAL(request.gross, 7);
        BOOST_CHECK_EQUAL(request.pool_id, marker);
    }
}

BOOST_AUTO_TEST_SUITE_END()
