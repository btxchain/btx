// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/matmul_block_lifecycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace std::chrono_literals;

BOOST_AUTO_TEST_SUITE(matmul_block_lifecycle_tests)

namespace {

std::shared_ptr<const CBlock> BlockWithNonce(uint32_t nonce)
{
    auto block{std::make_shared<CBlock>()};
    block->nVersion = 1;
    block->nTime = 1;
    block->nBits = 1;
    block->nNonce = nonce;
    return block;
}

node::MatMulBlockLifecycle::RetainedBody Body(uint32_t nonce,
                                               size_t bytes,
                                               std::chrono::steady_clock::time_point retry,
                                               uint64_t source_netgroup = 0)
{
    node::MatMulBlockLifecycle::RetainedBody body;
    body.block = BlockWithNonce(nonce);
    body.retry_not_before = retry;
    body.bytes = bytes;
    body.source_netgroup = source_netgroup;
    return body;
}

} // namespace

BOOST_AUTO_TEST_CASE(stale_callback_cannot_erase_new_generation)
{
    node::MatMulBlockLifecycle lifecycle{2, 200, 10min, 10s};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(1)->GetHash()};

    const auto first{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(lifecycle.Retry(*first, 0s, now + 1s));
    const auto second{lifecycle.Begin(hash, now + 2s)};
    BOOST_REQUIRE(second);
    BOOST_CHECK_NE(first->generation, second->generation);

    lifecycle.Terminal(*first); // late completion from the abandoned attempt
    BOOST_CHECK(lifecycle.IsActive(hash, now + 2s));
    BOOST_CHECK(lifecycle.Completing(*second, now + 3s));
    lifecycle.Terminal(*second);
    BOOST_CHECK(!lifecycle.StateForTest(hash));
}

BOOST_AUTO_TEST_CASE(hash_only_legacy_cleanup_cannot_mutate_active_generation)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "5").value()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(8, 50, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    auto lease{std::make_shared<int>(1)};
    std::weak_ptr<int> weak_lease{lease};
    BOOST_REQUIRE(lifecycle.Queue(
        *token, lease, std::make_shared<std::atomic_bool>(false), {}, now));
    lease.reset();

    BOOST_CHECK(!lifecycle.RetryInactive(hash, 60s, now + 1s));
    BOOST_CHECK(lifecycle.IsActive(hash, now + 1s));
    BOOST_CHECK(!weak_lease.expired());
}

BOOST_AUTO_TEST_CASE(stale_active_releases_slot_and_retains_body)
{
    node::MatMulBlockLifecycle lifecycle{2, 200, 10min, 5s};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const auto block{BlockWithNonce(2)};
    const uint256 hash{block->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(2, 80, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    auto lease{std::make_shared<int>(1)};
    std::weak_ptr<int> weak_lease{lease};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now));
    lease.reset();

    BOOST_CHECK_EQUAL(lifecycle.ExpireStaleAttempts(now + 6s), 1U);
    BOOST_CHECK(cancelled->load());
    BOOST_CHECK(weak_lease.expired());
    BOOST_CHECK_EQUAL(lifecycle.RetainedCountForTest(), 1U);
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 6s).has_value());
}

BOOST_AUTO_TEST_CASE(retry_cooldown_prevents_header_only_hot_loop)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "4").value()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(7, 50, now), now));
    BOOST_REQUIRE(lifecycle.NextRetry(uint256{}, now).has_value());

    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 59s).has_value());
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 60s).has_value());
}

BOOST_AUTO_TEST_CASE(wake_retry_once_does_not_erase_cooldown)
{
    using Reason = node::MatMulBlockLifecycle::RetryWakeReason;
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "5").value()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(7, 50, now), now));

    // A failed re-admission installs a 60s cooldown.
    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 30s).has_value());

    // First causal wake for a reason pulls the retry deadline to now.
    BOOST_CHECK(lifecycle.WakeRetryOnce(hash, Reason::RECOVERY_ROOT, now + 30s));
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 30s).has_value());

    // Re-arm the cooldown as another re-admission would, then hammer the same
    // reason: it must NOT overwrite the cooldown (the mainnet-201633 wedge).
    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now + 30s));
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(
            !lifecycle.WakeRetryOnce(hash, Reason::RECOVERY_ROOT, now + 31s + std::chrono::seconds{i}));
    }
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 60s).has_value());
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 30s + 60s).has_value());

    // A DISTINCT causal event still wakes the body exactly once.
    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now + 30s + 60s));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 30s + 90s).has_value());
    BOOST_CHECK(lifecycle.WakeRetryOnce(hash, Reason::TRUSTED_AUTHORITY, now + 30s + 90s));
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 30s + 90s).has_value());
}

BOOST_AUTO_TEST_CASE(repeated_deferral_terminal_requeues)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "6").value()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(9, 50, now), now));
    BOOST_CHECK_EQUAL(lifecycle.RetainedDeferralCount(hash), 0U);

    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now));
    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now + 1s));
    BOOST_CHECK_EQUAL(lifecycle.RetainedDeferralCount(hash), 2U);
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 30s).has_value());

    BOOST_REQUIRE(lifecycle.TerminalRequeue(hash, 60s, now + 2s));
    BOOST_CHECK_EQUAL(lifecycle.RetainedDeferralCount(hash), 0U);
    BOOST_CHECK(lifecycle.HasRetainedBody(hash));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 2s + 59s).has_value());
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 2s + 60s).has_value());
    BOOST_CHECK(!lifecycle.IsActive(hash, now + 2s));
}

BOOST_AUTO_TEST_CASE(idle_catchup_retry_bypass_is_one_shot)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "5").value()};
    auto body{Body(8, 50, now + 60s)};
    body.idle_retry_bypass_available = true;
    BOOST_REQUIRE(lifecycle.Retain(hash, std::move(body), now));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 1s).has_value());
    BOOST_CHECK(lifecycle.NextRetry(
        uint256{}, now + 1s, /*allow_idle_retry_bypass=*/true).has_value());
    BOOST_CHECK(!lifecycle.NextRetry(
        uint256{}, now + 2s, /*allow_idle_retry_bypass=*/true).has_value());
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 60s).has_value());
}

BOOST_AUTO_TEST_CASE(non_terminal_retry_disables_idle_bypass)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "d").value()};
    auto body{Body(13, 50, now)};
    body.idle_retry_bypass_available = true;
    BOOST_REQUIRE(lifecycle.Retain(hash, std::move(body), now));
    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now));
    BOOST_CHECK(!lifecycle.NextRetry(
        uint256{}, now + 1s, /*allow_idle_retry_bypass=*/true).has_value());
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 60s).has_value());
}

BOOST_AUTO_TEST_CASE(capacity_release_wakes_only_capacity_deferred_tip_child)
{
    using RetryCause = node::MatMulBlockLifecycle::RetryCause;

    node::MatMulBlockLifecycle lifecycle{3, 300, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 parent{
        uint256::FromHex(std::string(63, '0') + "c").value()};

    auto capacity_block{std::make_shared<CBlock>(*BlockWithNonce(12))};
    capacity_block->hashPrevBlock = parent;
    const uint256 capacity_hash{
        uint256::FromHex(std::string(63, '0') + "d").value()};
    auto capacity_body{Body(12, 50, now + 60s)};
    capacity_body.block = capacity_block;
    capacity_body.retry_cause = RetryCause::RC_PENDING_CAPACITY;
    BOOST_REQUIRE(lifecycle.Retain(
        capacity_hash, std::move(capacity_body), now));

    auto budget_block{std::make_shared<CBlock>(*BlockWithNonce(13))};
    budget_block->hashPrevBlock = parent;
    const uint256 budget_hash{
        uint256::FromHex(std::string(63, '0') + "e").value()};
    auto budget_body{Body(13, 50, now + 60s)};
    budget_body.block = budget_block;
    budget_body.retry_cause = RetryCause::TIMER_OR_AUTHORITY;
    BOOST_REQUIRE(lifecycle.Retain(budget_hash, std::move(budget_body), now));
    BOOST_CHECK_NE(capacity_hash, budget_hash);

    BOOST_CHECK(!lifecycle.NextRetry(parent, now + 1s));
    // An EncDr release cannot wake an RC-capacity deferral.
    BOOST_CHECK(!lifecycle.WakeCapacityRetry(
        parent, /*encdr_capacity_epoch=*/1, /*rc_capacity_epoch=*/0,
        now + 1s));
    const auto woken{lifecycle.WakeCapacityRetry(
        parent, /*encdr_capacity_epoch=*/0, /*rc_capacity_epoch=*/1,
        now + 1s)};
    BOOST_REQUIRE(woken);
    BOOST_CHECK_EQUAL(*woken, capacity_hash);
    const auto retry{lifecycle.NextRetry(parent, now + 1s)};
    BOOST_REQUIRE(retry);
    BOOST_CHECK_EQUAL(retry->first, capacity_hash);

    // A real later slot release is a new edge, not a level-triggered scan.
    // If another job won capacity, the same body may be woken again without
    // waiting for its 60-second fallback.
    BOOST_REQUIRE(lifecycle.RefreshRetry(
        capacity_hash, 60s, now + 1s,
        RetryCause::RC_PENDING_CAPACITY, /*capacity_epoch=*/1));
    BOOST_CHECK(!lifecycle.NextRetry(parent, now + 2s));
    BOOST_REQUIRE(lifecycle.WakeCapacityRetry(
        parent, /*encdr_capacity_epoch=*/0, /*rc_capacity_epoch=*/2,
        now + 2s));
    BOOST_CHECK(lifecycle.NextRetry(parent, now + 2s));

    // Capacity events never bypass a genuine rate/authority timer.
    lifecycle.TerminalRetained(capacity_hash);
    BOOST_CHECK(!lifecycle.WakeCapacityRetry(
        parent, /*encdr_capacity_epoch=*/1, /*rc_capacity_epoch=*/3,
        now + 3s));
    BOOST_CHECK(!lifecycle.NextRetry(parent, now + 3s));
    BOOST_CHECK(lifecycle.NextRetry(parent, now + 60s));
}

BOOST_AUTO_TEST_CASE(capacity_does_not_evict_active_generation)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 first_hash{
        uint256::FromHex(std::string(63, '0') + "1").value()};
    const uint256 second_hash{
        uint256::FromHex(std::string(63, '0') + "2").value()};
    BOOST_REQUIRE(lifecycle.Retain(first_hash, Body(3, 80, now), now));
    const auto token{lifecycle.Begin(first_hash, now)};
    BOOST_REQUIRE(token);
    BOOST_CHECK(!lifecycle.Retain(second_hash, Body(4, 30, now + 1s), now + 1s));
    BOOST_CHECK_EQUAL(lifecycle.RetainedCountForTest(), 1U);
    BOOST_CHECK(lifecycle.IsActive(first_hash, now + 1s));
}

BOOST_AUTO_TEST_CASE(park_releases_cap_and_terminal_frees_bytes)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const auto block{BlockWithNonce(5)};
    const uint256 hash{block->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(5, 75, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    auto lease{std::make_shared<int>(1)};
    std::weak_ptr<int> weak_lease{lease};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now));
    lease.reset();
    BOOST_REQUIRE(lifecycle.Start(*token, now));
    BOOST_REQUIRE(lifecycle.Park(*token, now + 1s));
    BOOST_CHECK(weak_lease.expired());
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 75U);

    lifecycle.Terminal(*token);
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 0U);
    BOOST_CHECK_EQUAL(lifecycle.RetainedCountForTest(), 0U);
}

BOOST_AUTO_TEST_CASE(connected_block_clears_live_lifecycle_generation)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const auto block{BlockWithNonce(14)};
    const uint256 hash{block->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(14, 75, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    auto lease{std::make_shared<int>(1)};
    std::weak_ptr<int> weak_lease{lease};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now));
    lease.reset();
    BOOST_REQUIRE(lifecycle.Start(*token, now));

    lifecycle.TerminalConnected(hash);
    // Deployment-blocker fix (PR #132 review): a RUNNING full-body replay
    // bypasses the cancel latch (ProtectsBodyReplay) and still owns the lease /
    // capacity. TerminalConnected must therefore raise the terminal signal but
    // NOT release capacity/lease -- that stays owned until the worker
    // acknowledges via Terminal()/Retry(). Otherwise the running replay executes
    // against capacity already reported free.
    BOOST_CHECK(cancelled->load());               // terminal signal raised
    BOOST_CHECK(!weak_lease.expired());           // lease NOT released early
    BOOST_CHECK(lifecycle.StateForTest(hash).has_value()); // entry retained
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 75U); // capacity owned

    lifecycle.Terminal(*token); // worker acknowledges completion -> now cleared
    BOOST_CHECK(weak_lease.expired());
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 0U);
}

// A terminal_on_connect entry that goes stale (worker still in flight after the
// 10-min window) must be ERASED by stale expiry, not flipped to a retryable
// body -- otherwise NextRetry re-admits an already-connected hash and reopens
// the lease/capacity double-book the deferred-erase fix closed.
BOOST_AUTO_TEST_CASE(connected_block_stale_expiry_erases_not_readmits)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const auto block{BlockWithNonce(21)};
    const uint256 hash{block->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(21, 75, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    auto lease{std::make_shared<int>(1)};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now));
    lease.reset();
    BOOST_REQUIRE(lifecycle.Start(*token, now));

    lifecycle.TerminalConnected(hash); // block connected while replay in flight
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 75U); // still owned

    // Worker still has not acknowledged 11 min later: stale expiry fires.
    const auto later{now + 11min};
    BOOST_CHECK_EQUAL(lifecycle.ExpireStaleAttempts(later), 1U);
    // Erased with accounting released -- NOT left as a retryable body.
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
    BOOST_CHECK_EQUAL(lifecycle.RetainedCountForTest(), 0U);
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 0U);
    // And it is never handed back out for re-admission.
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, later).has_value());
}

// The connected hash must never be re-admitted: a retryable-failure completion
// arriving after TerminalConnected ERASES the entry rather than retaining it.
BOOST_AUTO_TEST_CASE(connected_block_retry_does_not_readmit)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const auto block{BlockWithNonce(15)};
    const uint256 hash{block->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(15, 75, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    auto lease{std::make_shared<int>(1)};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now));
    lease.reset();
    BOOST_REQUIRE(lifecycle.Start(*token, now));

    lifecycle.TerminalConnected(hash);            // block connected mid-replay
    BOOST_REQUIRE(lifecycle.StateForTest(hash).has_value()); // deferred

    // Worker acknowledges a retryable failure: must ERASE (not retain) -- the
    // hash is on the active chain, so it must not become a retry candidate.
    BOOST_CHECK(lifecycle.Retry(*token, 60s, now));
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 120s).has_value());
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 0U);
}

BOOST_AUTO_TEST_CASE(async_pending_without_body_does_not_block_download)
{
    // FindNextBlocks invariant: async-pending is a VERIFY state. A marker
    // without HAVE_DATA / without a retained body must be reclaimed so the
    // hash is getdata'd. A marker that already has a body (HAVE_DATA analog)
    // must remain so duplicate verify is skipped.
    node::MatMulBlockLifecycle lifecycle{2, 200, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};

    const uint256 missing_hash{
        uint256::FromHex(std::string(63, '0') + "a").value()};
    BOOST_REQUIRE(lifecycle.Begin(missing_hash, now));
    BOOST_CHECK(lifecycle.IsActive(missing_hash, now));
    // Hash-only RetryInactive must not clear a live generation (even with
    // no body). That was the production Unmark pitfall.
    BOOST_CHECK(!lifecycle.RetryInactive(missing_hash, 0s, now));
    BOOST_CHECK(lifecycle.IsActive(missing_hash, now));
    BOOST_CHECK(lifecycle.ExpireActiveWithoutBody(missing_hash, now));
    BOOST_CHECK(!lifecycle.IsActive(missing_hash, now));
    BOOST_CHECK(!lifecycle.StateForTest(missing_hash));

    BOOST_REQUIRE(lifecycle.Begin(missing_hash, now + 1s));
    // No HAVE_DATA: reclaim and request. Must not skip.
    BOOST_CHECK(!lifecycle.ShouldSkipFetchWhileAsyncPending(
        missing_hash, /*have_data=*/false, now + 1s));
    BOOST_CHECK(!lifecycle.IsActive(missing_hash, now + 1s));
    // Second pass is a no-op: hash stays requestable.
    BOOST_CHECK(!lifecycle.ShouldSkipFetchWhileAsyncPending(
        missing_hash, /*have_data=*/false, now + 2s));

    const uint256 have_data_hash{
        uint256::FromHex(std::string(63, '0') + "b").value()};
    BOOST_REQUIRE(lifecycle.Retain(have_data_hash, Body(9, 50, now), now));
    BOOST_CHECK(lifecycle.HasRetainedBody(have_data_hash));
    BOOST_REQUIRE(lifecycle.Begin(have_data_hash, now));
    BOOST_CHECK(lifecycle.IsActive(have_data_hash, now));
    BOOST_CHECK(!lifecycle.ExpireActiveWithoutBody(have_data_hash, now));
    BOOST_CHECK(lifecycle.IsActive(have_data_hash, now));
    // HAVE_DATA: skip duplicate verify.
    BOOST_CHECK(lifecycle.ShouldSkipFetchWhileAsyncPending(
        have_data_hash, /*have_data=*/true, now));
    BOOST_CHECK(lifecycle.IsActive(have_data_hash, now));
    // Retained body without HAVE_DATA is still verify-in-flight: skip
    // duplicate getdata, do not expire the live generation.
    BOOST_CHECK(lifecycle.ShouldSkipFetchWhileAsyncPending(
        have_data_hash, /*have_data=*/false, now));
    BOOST_CHECK(lifecycle.IsActive(have_data_hash, now));
}

BOOST_AUTO_TEST_CASE(progress_vector_tracks_causal_events_not_time)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const auto initial{lifecycle.Progress()};

    // Wall-clock movement alone is deliberately not progress.
    (void)lifecycle.ExpireStaleAttempts(now + 1s);
    BOOST_CHECK(lifecycle.Progress() == initial);

    lifecycle.NoteHeaderProgress();
    auto current{lifecycle.Progress()};
    BOOST_CHECK_EQUAL(current.header, initial.header + 1);
    BOOST_CHECK_EQUAL(current.body, initial.body);
    BOOST_CHECK_EQUAL(current.active_tip, initial.active_tip);

    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "3").value()};
    lifecycle.NoteBodyProgress();
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(6, 50, now), now));
    current = lifecycle.Progress();
    BOOST_CHECK_EQUAL(current.body, initial.body + 1);
    BOOST_CHECK_EQUAL(current.verify_started, initial.verify_started);

    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    BOOST_REQUIRE(lifecycle.Queue(
        *token, {}, std::make_shared<std::atomic_bool>(false), {}, now));
    BOOST_REQUIRE(lifecycle.Start(*token, now));
    current = lifecycle.Progress();
    BOOST_CHECK_EQUAL(current.verify_started, initial.verify_started + 1);
    BOOST_CHECK_EQUAL(current.verify_completed, initial.verify_completed);

    BOOST_REQUIRE(lifecycle.Completing(*token, now));
    current = lifecycle.Progress();
    BOOST_CHECK_EQUAL(current.verify_completed,
                      initial.verify_completed + 1);
    lifecycle.NoteActiveTipProgress();
    current = lifecycle.Progress();
    BOOST_CHECK_EQUAL(current.active_tip, initial.active_tip + 1);
}

BOOST_AUTO_TEST_CASE(retained_body_is_skip_fetch_until_terminal)
{
    // Ticketless followed-chain retain: skip-fetch while the only copy is
    // held. Terminal release (ticket/retry success, invalid, capacity) is
    // what invalidates the skip, not a 60s wall-clock expiry.
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "9").value()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(9, 50, now), now));
    BOOST_CHECK(lifecycle.HasRetainedBody(hash));
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now).has_value());
    lifecycle.TerminalRetained(hash);
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
}

BOOST_AUTO_TEST_CASE(pinned_progress_body_survives_sibling_flood)
{
    node::MatMulBlockLifecycle lifecycle{2, 200, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hole{
        uint256::FromHex(std::string(63, '0') + "a").value()};
    auto pinned{Body(10, 50, now)};
    pinned.pin_progress = true;
    BOOST_REQUIRE(lifecycle.Retain(hole, std::move(pinned), now));
    const uint256 junk{
        uint256::FromHex(std::string(63, '0') + "b").value()};
    BOOST_REQUIRE(lifecycle.Retain(junk, Body(11, 50, now + 1s), now + 1s));
    const uint256 junk2{
        uint256::FromHex(std::string(63, '0') + "c").value()};
    BOOST_REQUIRE(lifecycle.Retain(junk2, Body(12, 50, now + 2s), now + 2s));
    BOOST_CHECK(lifecycle.HasRetainedBody(hole));
    BOOST_CHECK(!lifecycle.HasRetainedBody(junk));
    BOOST_CHECK(lifecycle.HasRetainedBody(junk2));
}

BOOST_AUTO_TEST_CASE(per_source_caps_cannot_starve_other_netgroup)
{
    // SF-8: one netgroup filling the store must evict its own oldest
    // bodies first and must not prevent an independent source from
    // retaining.
    node::MatMulBlockLifecycle lifecycle{8, 1000, 10min, 10s, 2, 250};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    std::vector<uint256> attacker;
    auto t{now};
    for (int i = 0; i < 6; ++i) {
        const uint256 hash{
            uint256::FromHex(std::string(62, '0') +
                             strprintf("%02x", 0x31 + i)).value()};
        attacker.push_back(hash);
        BOOST_REQUIRE(lifecycle.Retain(
            hash, Body(21 + i, 50, t, /*source_netgroup=*/1), t));
        t += 1s;
    }
    BOOST_CHECK_EQUAL(lifecycle.RetainedCountForSourceForTest(1), 2U);
    BOOST_CHECK_LE(lifecycle.RetainedCountForTest(), 8U);
    BOOST_CHECK(!lifecycle.HasRetainedBody(attacker[0]));
    BOOST_CHECK(!lifecycle.HasRetainedBody(attacker[1]));
    BOOST_CHECK(!lifecycle.HasRetainedBody(attacker[2]));
    BOOST_CHECK(!lifecycle.HasRetainedBody(attacker[3]));
    BOOST_CHECK(lifecycle.HasRetainedBody(attacker[4]));
    BOOST_CHECK(lifecycle.HasRetainedBody(attacker[5]));

    const uint256 honest{
        uint256::FromHex(std::string(62, '0') + "40").value()};
    BOOST_REQUIRE(lifecycle.Retain(
        honest, Body(40, 50, t, /*source_netgroup=*/2), t));
    BOOST_CHECK(lifecycle.HasRetainedBody(honest));
    BOOST_CHECK_EQUAL(lifecycle.RetainedCountForSourceForTest(1), 2U);
    BOOST_CHECK_EQUAL(lifecycle.RetainedCountForSourceForTest(2), 1U);
    BOOST_CHECK(lifecycle.HasRetainedBody(attacker[4]));
    BOOST_CHECK(lifecycle.HasRetainedBody(attacker[5]));
    BOOST_CHECK_LE(lifecycle.RetainedCountForTest(), 8U);
}

BOOST_AUTO_TEST_SUITE_END()
