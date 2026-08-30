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

BOOST_AUTO_TEST_CASE(idle_scheduler_honors_retry_cooldown)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "5").value()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(8, 50, now), now));
    BOOST_REQUIRE(lifecycle.RefreshRetry(hash, 60s, now));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 1s).has_value());
    BOOST_CHECK(lifecycle.NextRetry(uint256{}, now + 60s).has_value());
}

BOOST_AUTO_TEST_CASE(terminal_requeue_preserves_original_retention_ttl)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{
        uint256::FromHex(std::string(63, '0') + "7").value()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(10, 50, now), now));
    BOOST_REQUIRE(lifecycle.TerminalRequeue(hash, 60s, now + 9min));
    BOOST_CHECK(lifecycle.HasRetainedBody(hash));

    // Requeueing at minute nine must not restart the ten-minute capacity TTL.
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 10min + 1s).has_value());
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
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
    BOOST_CHECK(cancelled->load());
    BOOST_CHECK(weak_lease.expired());
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
    BOOST_CHECK_EQUAL(lifecycle.RetainedBytesForTest(), 0U);

    lifecycle.Terminal(*token); // late completion is a harmless no-op
    BOOST_CHECK(!lifecycle.StateForTest(hash));
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

// --- PR #132 P1: terminal (block-connected) cancellation holds the admission
// --- lease until the worker acknowledges, then releases it exactly once with
// --- no re-admission; preserves the generation-race fix.

namespace {
//! Model of the RC admission lease/counter (ScopedMatMulPendingVerification):
//! occupied while a shared_ptr<void> lease is held, released exactly once when
//! the lifecycle drops it.
std::shared_ptr<void> MakeCountedLease(std::atomic<int>& counter)
{
    counter.fetch_add(1);
    return std::shared_ptr<void>(reinterpret_cast<void*>(0x1),
                                 [&counter](void*) { counter.fetch_sub(1); });
}
} // namespace

BOOST_AUTO_TEST_CASE(terminal_connected_holds_running_lease_until_worker_ack)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(21)->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(21, 50, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    std::atomic<int> counter{0};
    auto lease{MakeCountedLease(counter)};
    std::weak_ptr<void> weak_lease{lease};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    auto terminated{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now, terminated));
    lease.reset(); // only the lifecycle entry holds the lease now
    BOOST_REQUIRE(lifecycle.Start(*token, now)); // RUNNING
    BOOST_CHECK_EQUAL(counter.load(), 1);
    BOOST_CHECK(!weak_lease.expired());

    // Block connects; a worker owns the running replay and will acknowledge.
    lifecycle.TerminalConnected(hash, /*worker_will_ack=*/true);
    BOOST_CHECK(terminated->load());   // terminal signal raised
    BOOST_CHECK(cancelled->load());
    BOOST_CHECK(lifecycle.PendingLeaseHeldForTest(hash)); // HELD, not released
    BOOST_CHECK_EQUAL(counter.load(), 1);
    BOOST_CHECK(!weak_lease.expired());
    BOOST_CHECK(lifecycle.StateForTest(hash).has_value());

    // Worker acknowledges via the terminal path (lifecycle.Terminal).
    lifecycle.Terminal(*token);
    BOOST_CHECK_EQUAL(counter.load(), 0);   // released exactly once
    BOOST_CHECK(weak_lease.expired());
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash)); // no retained body -> no re-admission
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 20min).has_value());
}

BOOST_AUTO_TEST_CASE(terminal_connected_holds_queued_lease_until_worker_ack)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(22)->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(22, 50, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    std::atomic<int> counter{0};
    auto lease{MakeCountedLease(counter)};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    auto terminated{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now, terminated));
    lease.reset(); // QUEUED (not started); only the entry holds the lease
    BOOST_CHECK_EQUAL(counter.load(), 1);

    lifecycle.TerminalConnected(hash, /*worker_will_ack=*/true);
    BOOST_CHECK(terminated->load());
    BOOST_CHECK(lifecycle.PendingLeaseHeldForTest(hash)); // held until ack
    BOOST_CHECK_EQUAL(counter.load(), 1);

    lifecycle.Terminal(*token);
    BOOST_CHECK_EQUAL(counter.load(), 0);
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
}

BOOST_AUTO_TEST_CASE(terminal_connected_no_worker_ack_releases_immediately)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(23)->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(23, 50, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    std::atomic<int> counter{0};
    auto lease{MakeCountedLease(counter)};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    auto terminated{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now, terminated));
    lease.reset();
    BOOST_REQUIRE(lifecycle.Start(*token, now));
    BOOST_CHECK_EQUAL(counter.load(), 1);

    // No worker can acknowledge: cleanup completes immediately (no stick).
    lifecycle.TerminalConnected(hash, /*worker_will_ack=*/false);
    BOOST_CHECK(terminated->load());
    BOOST_CHECK_EQUAL(counter.load(), 0);   // released now, exactly once
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
}

BOOST_AUTO_TEST_CASE(terminal_connected_admission_pending_erases_and_blocks_queue)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(24)->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(24, 50, now), now));
    const auto token{lifecycle.Begin(hash, now)}; // ADMISSION_PENDING, no lease yet
    BOOST_REQUIRE(token);

    // No worker job exists yet -> immediate cleanup; the pending Queue then fails.
    lifecycle.TerminalConnected(hash, /*worker_will_ack=*/false);
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    std::atomic<int> counter{0};
    auto lease{MakeCountedLease(counter)};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    auto terminated{std::make_shared<std::atomic_bool>(false)};
    BOOST_CHECK(!lifecycle.Queue(*token, lease, cancelled, {}, now, terminated));
}

BOOST_AUTO_TEST_CASE(terminal_connected_admission_pending_no_ack_with_same_hash_worker)
{
    // worker_will_ack is hash-keyed: a same-hash header-first worker returns
    // true even though it does not own this generation's body attempt.
    // ADMISSION_PENDING (no lease, body attempt not yet handed to the worker)
    // must be treated as no-ack and cleaned up immediately, never held.
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(27)->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(27, 50, now), now));
    const auto token{lifecycle.Begin(hash, now)}; // ADMISSION_PENDING
    BOOST_REQUIRE(token);

    lifecycle.TerminalConnected(hash, /*worker_will_ack=*/true);
    BOOST_CHECK(!lifecycle.StateForTest(hash));            // erased immediately
    BOOST_CHECK(!lifecycle.PendingLeaseHeldForTest(hash)); // nothing held
    // The pending body Queue then fails (entry gone) -> caller rolls back.
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    auto terminated{std::make_shared<std::atomic_bool>(false)};
    BOOST_CHECK(!lifecycle.Queue(*token, nullptr, cancelled, {}, now, terminated));
}

BOOST_AUTO_TEST_CASE(terminal_retry_erases_body_no_readmission)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(25)->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(25, 50, now), now));
    const auto token{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token);
    std::atomic<int> counter{0};
    auto lease{MakeCountedLease(counter)};
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    auto terminated{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token, lease, cancelled, {}, now, terminated));
    lease.reset();
    BOOST_REQUIRE(lifecycle.Start(*token, now));

    lifecycle.TerminalConnected(hash, /*worker_will_ack=*/true); // terminated + held
    BOOST_CHECK(lifecycle.PendingLeaseHeldForTest(hash));

    // Defense-in-depth: even if the worker acks via the retryable path, a
    // terminated entry is erased (its body is NOT kept retryable).
    BOOST_REQUIRE(lifecycle.Retry(*token, 60s, now));
    BOOST_CHECK_EQUAL(counter.load(), 0);
    BOOST_CHECK(!lifecycle.StateForTest(hash));
    BOOST_CHECK(!lifecycle.HasRetainedBody(hash));
    BOOST_CHECK(!lifecycle.NextRetry(uint256{}, now + 20min).has_value());
}

BOOST_AUTO_TEST_CASE(terminal_ack_is_generation_scoped)
{
    node::MatMulBlockLifecycle lifecycle{1, 100, 10min, 10min};
    const auto now{node::MatMulBlockLifecycle::Clock::now()};
    const uint256 hash{BlockWithNonce(26)->GetHash()};
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(26, 50, now), now));
    const auto token1{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token1);
    auto cancelled{std::make_shared<std::atomic_bool>(false)};
    auto terminated{std::make_shared<std::atomic_bool>(false)};
    BOOST_REQUIRE(lifecycle.Queue(*token1, nullptr, cancelled, {}, now, terminated));
    BOOST_REQUIRE(lifecycle.Start(*token1, now));
    lifecycle.TerminalConnected(hash, /*worker_will_ack=*/true);
    lifecycle.Terminal(*token1); // gen1 acknowledged + erased

    // A reorg re-retains and starts a FRESH generation for the same hash.
    BOOST_REQUIRE(lifecycle.Retain(hash, Body(26, 50, now), now));
    const auto token2{lifecycle.Begin(hash, now)};
    BOOST_REQUIRE(token2);
    BOOST_CHECK(token2->generation != token1->generation);

    // A late/stale acknowledgement for gen1 must NOT erase gen2 (generation-race fix).
    lifecycle.Terminal(*token1);
    BOOST_CHECK(lifecycle.StateForTest(hash).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
