// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MATMUL_BLOCK_LIFECYCLE_H
#define BITCOIN_NODE_MATMUL_BLOCK_LIFECYCLE_H

#include <netaddress.h>
#include <primitives/block.h>
#include <uint256.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace node {

/**
 * Authoritative ownership for the expensive MatMul block-validation lifecycle.
 *
 * Block transport remains owned by net_processing's ordinary in-flight map.
 * Once a complete body reaches expensive admission, however, this table is the
 * single owner of the retained body, async generation, cancellation token, and
 * pending-work lease.  Generation-bound transitions make a late callback from
 * an abandoned attempt harmless: it cannot release or overwrite a newer
 * attempt for the same hash.
 */
class MatMulBlockLifecycle
{
public:
    using Clock = std::chrono::steady_clock;

    /**
     * Causal events that may make an inactive retained body immediately
     * admissible. Each event wakes a retained generation at most once so a
     * level-triggered peer scan cannot continuously erase a retry cooldown
     * (mainnet-201633 1Hz re-admission wedge, dev a16476cf).
     */
    enum class RetryWakeReason : uint8_t {
        RECOVERY_ROOT = 0,
        TRUSTED_AUTHORITY = 1,
    };

    enum class State : uint8_t {
        BODY_RETAINED,
        ADMISSION_PENDING,
        QUEUED,
        RUNNING,
        AWAITING_QUORUM,
        COMPLETING,
        TRANSIENT_FAILURE,
    };

    struct RetainedBody {
        std::shared_ptr<const CBlock> block;
        Clock::time_point stored_at{};
        Clock::time_point retry_not_before{};
        size_t bytes{0};
        int64_t source_peer{-1};
        CNetAddr source_address{};
        uint64_t source_netgroup{0};
        bool source_punishable{true};
        bool force_processing{false};
        bool min_pow_checked{false};
        bool is_ibd{false};
        int32_t reference_height{std::numeric_limits<int32_t>::max()};
        uint32_t work_units{0};
        //! Canonical first-hole / followed tip-child: OldestEvictable skips
        //! these so a sibling-body flood cannot drop the progress body (4.2).
        bool pin_progress{false};
        //! Non-terminal deferrals since this body was last freshly retained.
        //! RefreshRetry increments; TerminalRequeue resets.
        uint32_t deferral_count{0};
        //! RetryWakeReason bits already consumed by this retained generation.
        //! Terminal requeue and repeated delivery preserve these bits so a
        //! level-triggered peer scan wakes each reason at most once.
        uint8_t retry_wake_mask{0};
        //! A newly budget-deferred body may bypass its first retry deadline
        //! when the verifier is otherwise idle. The bypass is consumed by
        //! NextRetry so idle catch-up cannot defeat every later cooldown.
        bool idle_retry_bypass_available{false};
    };

    struct Token {
        uint256 hash;
        uint64_t generation{0};

        explicit operator bool() const { return generation != 0; }
    };

    /** Monotonic causal progress, deliberately independent of wall clock. */
    struct ProgressVector {
        uint64_t header{0};
        uint64_t body{0};
        uint64_t verify_started{0};
        uint64_t verify_completed{0};
        uint64_t active_tip{0};

        bool operator==(const ProgressVector&) const = default;
    };

    void NoteHeaderProgress()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_progress.header;
    }

    void NoteActiveTipProgress()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_progress.active_tip;
    }

    void NoteBodyProgress()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_progress.body;
    }

    ProgressVector Progress() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_progress;
    }

    MatMulBlockLifecycle(size_t max_retained_count,
                         size_t max_retained_bytes,
                         Clock::duration retained_max_age,
                         Clock::duration async_stale_after,
                         size_t max_retained_count_per_source =
                             std::numeric_limits<size_t>::max(),
                         size_t max_retained_bytes_per_source =
                             std::numeric_limits<size_t>::max())
        : m_max_retained_count{max_retained_count},
          m_max_retained_bytes{max_retained_bytes},
          m_max_retained_count_per_source{max_retained_count_per_source},
          m_max_retained_bytes_per_source{max_retained_bytes_per_source},
          m_retained_max_age{retained_max_age},
          m_async_stale_after{async_stale_after}
    {
    }

    /** Begin one expensive attempt. Duplicate live attempts are rejected. */
    std::optional<Token> Begin(const uint256& hash,
                               Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ExpireStaleAttempt(hash, now);
        auto [it, inserted] = m_entries.try_emplace(hash);
        Entry& entry{it->second};
        if (!inserted && IsActive(entry.state)) return std::nullopt;
        entry.state = State::ADMISSION_PENDING;
        entry.updated_at = now;
        entry.pending_lease.reset();
        entry.cancelled = std::make_shared<std::atomic_bool>(false);
        entry.generation = NextGeneration();
        return Token{hash, entry.generation};
    }

    bool IsActive(const uint256& hash,
                  Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ExpireStaleAttempt(hash, now);
        const auto it{m_entries.find(hash)};
        return it != m_entries.end() && IsActive(it->second.state);
    }

    size_t ExpireStaleAttempts(Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t expired{0};
        for (auto it = m_entries.begin(); it != m_entries.end();) {
            if (!IsActive(it->second.state) ||
                now - it->second.updated_at <= m_async_stale_after) {
                ++it;
                continue;
            }
            ++expired;
            if (it->second.cancelled) {
                it->second.cancelled->store(true, std::memory_order_relaxed);
            }
            it->second.pending_lease.reset();
            it->second.cancelled.reset();
            // A block that connected while this replay was in flight
            // (terminal_on_connect) must never be flipped back to a retryable
            // body by stale expiry -- that reopens the re-admission the deferred
            // erase closed. Release its accounting and erase, exactly as the
            // worker-acknowledged Retry()/Terminal() would.
            if (it->second.body && !it->second.terminal_on_connect) {
                it->second.state = State::TRANSIENT_FAILURE;
                it->second.updated_at = now;
                ++it;
            } else {
                if (it->second.body) {
                    AccountSourceRemove(it->second.body->source_netgroup,
                                        it->second.body->bytes);
                    m_retained_bytes -= it->second.body->bytes;
                }
                it = m_entries.erase(it);
            }
        }
        return expired;
    }

    /**
     * Retain or refresh a body. Active entries are never capacity-evicted;
     * eviction is restricted to retryable retained entries.
     */
    bool Retain(const uint256& hash, RetainedBody body,
                Clock::time_point now = Clock::now())
    {
        if (!body.block || body.bytes > m_max_retained_bytes) return false;
        if (body.bytes > m_max_retained_bytes_per_source) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        PruneExpiredRetained(now);

        auto existing{m_entries.find(hash)};
        const size_t old_bytes{
            existing != m_entries.end() && existing->second.body
                ? existing->second.body->bytes
                : 0};
        const size_t old_count{old_bytes != 0 ? 1U : 0U};
        const uint64_t src{body.source_netgroup};
        const bool replacing_same_source{
            existing != m_entries.end() && existing->second.body &&
            existing->second.body->source_netgroup == src};
        const size_t old_src_count{replacing_same_source ? 1U : 0U};
        const size_t old_src_bytes{replacing_same_source ? old_bytes : 0U};
        while (SourceCount(src) - old_src_count + 1 >
                   m_max_retained_count_per_source ||
               SourceBytes(src) - old_src_bytes + body.bytes >
                   m_max_retained_bytes_per_source) {
            auto victim{OldestEvictableForSource(hash, src)};
            if (victim == m_entries.end()) return false;
            RecordEvictionTombstone(victim, now);
            EraseEntry(victim);
        }
        while (RetainedCount() - old_count + 1 > m_max_retained_count ||
               m_retained_bytes - old_bytes + body.bytes >
                   m_max_retained_bytes) {
            auto victim{OldestEvictable(hash)};
            if (victim == m_entries.end()) return false;
            RecordEvictionTombstone(victim, now);
            EraseEntry(victim);
        }

        auto [it, inserted] = m_entries.try_emplace(hash);
        Entry& entry{it->second};
        auto original_stored_at{entry.body ? entry.body->stored_at : now};
        bool idle_retry_bypass_available{
            entry.body ? entry.body->idle_retry_bypass_available
                       : body.idle_retry_bypass_available};
        auto original_deferral_count{
            entry.body ? entry.body->deferral_count : body.deferral_count};
        uint8_t original_retry_wake_mask{
            entry.body ? entry.body->retry_wake_mask : uint8_t{0}};
        if (!entry.body) {
            // Fresh insert. If this hash was recently EVICTED under capacity
            // pressure, its tombstone carries the original freshness so an
            // evict+re-deliver cannot refresh the non-refreshing capacity TTL,
            // reset the deferral count below the TerminalRequeue threshold, or
            // re-grant a consumed idle bypass (cmpl-netdos F1).
            if (auto ts = m_eviction_tombstones.find(hash);
                ts != m_eviction_tombstones.end()) {
                if (now - ts->second.tombstoned_at <= m_retained_max_age) {
                    original_stored_at = ts->second.stored_at;
                    original_deferral_count = ts->second.deferral_count;
                    idle_retry_bypass_available =
                        ts->second.idle_retry_bypass_available;
                    // Extend the non-refreshing protection to the wake mask so
                    // an evict+re-deliver cannot re-arm a consumed wake either
                    // (audit F3: symmetric with in-place Retain/TerminalRequeue).
                    original_retry_wake_mask |= ts->second.retry_wake_mask;
                }
                m_eviction_tombstones.erase(ts);
            }
        }
        if (entry.body) {
            AccountSourceRemove(entry.body->source_netgroup, entry.body->bytes);
            m_retained_bytes -= entry.body->bytes;
        }
        // Capacity TTL is non-refreshing for a hash: retries or repeated
        // deliveries (including evict+re-deliver) cannot pin retained bytes.
        body.stored_at = original_stored_at;
        body.deferral_count = original_deferral_count;
        // A repeated delivery keeps every wake bit the retained generation
        // already consumed, so it cannot re-arm a wake to erase a cooldown.
        body.retry_wake_mask |= original_retry_wake_mask;
        // A duplicate delivery for the same hash must not restore a bypass
        // already consumed by the scheduler.
        body.idle_retry_bypass_available = idle_retry_bypass_available;
        entry.body = std::move(body);
        AccountSourceAdd(entry.body->source_netgroup, entry.body->bytes);
        m_retained_bytes += entry.body->bytes;
        if (inserted || !IsActive(entry.state)) {
            entry.state = State::BODY_RETAINED;
            entry.updated_at = now;
        }
        return true;
    }

    /**
     * Make one retained body immediately retryable for a newly satisfied
     * causal condition, without counting the wake as another deferral.
     *
     * Unlike RefreshRetry(hash, 0), repeated calls for the same reason do not
     * overwrite a cooldown installed by a failed re-admission. A later,
     * distinct event (for example trusted authority arriving after recovery
     * selection) may still wake the body once. This is the edge-triggered
     * replacement for the level-triggered RefreshRetry(0) peer-scan wakes that
     * produced the mainnet-201633 1Hz re-admission wedge (dev a16476cf).
     */
    bool WakeRetryOnce(const uint256& hash, RetryWakeReason reason,
                       Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || !it->second.body ||
            IsActive(it->second.state)) {
            return false;
        }
        const uint8_t bit{static_cast<uint8_t>(
            uint8_t{1} << static_cast<uint8_t>(reason))};
        if ((it->second.body->retry_wake_mask & bit) != 0) return false;
        it->second.body->retry_wake_mask |= bit;
        if (it->second.body->retry_not_before > now) {
            it->second.body->retry_not_before = now;
        }
        return true;
    }

    /** Drop every retained body and attempt. Shared peerman fixtures must
     *  call this between cases so leftover RUNNING/BODY_RETAINED entries
     *  cannot fill capacity or starve the next Retain. */
    void ClearForTest()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        while (!m_entries.empty()) {
            EraseEntry(m_entries.begin());
        }
    }

    std::optional<std::pair<uint256, RetainedBody>> NextRetry(
        const uint256& preferred_parent,
        Clock::time_point now = Clock::now(),
        bool allow_idle_retry_bypass = false)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        PruneExpiredRetained(now);
        auto selected{m_entries.end()};
        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            const Entry& entry{it->second};
            // Never re-admit a hash whose block already connected while its
            // replay was in flight; such an entry is awaiting worker-ack erase.
            if (!entry.body || IsActive(entry.state) ||
                entry.terminal_on_connect) {
                continue;
            }
            const bool retry_due{now >= entry.body->retry_not_before};
            const bool may_bypass{
                allow_idle_retry_bypass &&
                entry.body->idle_retry_bypass_available};
            if (!retry_due && !may_bypass) {
                continue;
            }
            if (entry.body->block->hashPrevBlock == preferred_parent) {
                selected = it;
                break;
            }
            if (selected == m_entries.end() ||
                entry.body->stored_at < selected->second.body->stored_at) {
                selected = it;
            }
        }
        if (selected == m_entries.end()) return std::nullopt;
        if (now < selected->second.body->retry_not_before) {
            selected->second.body->idle_retry_bypass_available = false;
        }
        return std::make_pair(selected->first, *selected->second.body);
    }

    bool RefreshRetry(const uint256& hash, Clock::duration delay,
                      Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || !it->second.body) return false;
        it->second.body->retry_not_before = now + delay;
        it->second.body->idle_retry_bypass_available = false;
        ++it->second.body->deferral_count;
        return true;
    }

    uint32_t RetainedDeferralCount(const uint256& hash) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || !it->second.body) return 0;
        return it->second.body->deferral_count;
    }

    /**
     * Drop a stale inactive retained generation and re-install the body
     * as a fresh retry. Repeated non-terminal deferral used to leave the
     * same entry in BODY_RETAINED forever; after a few cycles the
     * scheduler must requeue rather than spin.
     */
    bool TerminalRequeue(const uint256& hash, Clock::duration delay,
                         Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || !it->second.body ||
            IsActive(it->second.state)) {
            return false;
        }
        RetainedBody body{*it->second.body};
        EraseEntry(it);
        body.deferral_count = 0;
        // Do NOT reset stored_at: the capacity TTL is non-refreshing for a
        // hash, matching the same-entry Retain() guarantee. Resetting it here
        // let a repeatedly-deferred (3+ deferrals -> TerminalRequeue) body keep
        // renewing its freshness and defeat the 45-min PruneExpiredRetained
        // backstop, pinning retained bytes and skewing oldest-first eviction
        // against honest bodies (final-lifecycle audit F1). `body` is a copy of
        // the existing entry, so it already carries the original stored_at.
        body.retry_not_before = now + delay;
        body.idle_retry_bypass_available = false;
        auto [nit, inserted] = m_entries.try_emplace(hash);
        (void)inserted;
        Entry& entry{nit->second};
        entry.body = std::move(body);
        AccountSourceAdd(entry.body->source_netgroup, entry.body->bytes);
        m_retained_bytes += entry.body->bytes;
        entry.state = State::BODY_RETAINED;
        entry.updated_at = now;
        entry.generation = 0;
        return true;
    }

    bool Queue(const Token& token, std::shared_ptr<void> pending_lease,
               const std::shared_ptr<std::atomic_bool>& cancelled,
               std::vector<std::shared_ptr<void>> owned_resources = {},
               Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Entry* entry{Find(token)};
        if (!entry || entry->state != State::ADMISSION_PENDING) return false;
        entry->pending_lease = std::move(pending_lease);
        entry->cancelled = cancelled;
        entry->owned_resources = std::move(owned_resources);
        entry->state = State::QUEUED;
        entry->updated_at = now;
        return true;
    }

    bool Start(const Token& token, Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Entry* entry{Find(token)};
        if (!entry || (entry->state != State::QUEUED &&
                       entry->state != State::AWAITING_QUORUM)) {
            return false;
        }
        entry->state = State::RUNNING;
        entry->updated_at = now;
        ++m_progress.verify_started;
        return true;
    }

    /** Waiting for signatures owns retained bytes, but no compute slot. */
    bool Park(const Token& token, Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Entry* entry{Find(token)};
        if (!entry || entry->state != State::RUNNING) return false;
        entry->pending_lease.reset();
        entry->state = State::AWAITING_QUORUM;
        entry->updated_at = now;
        return true;
    }

    bool Completing(const Token& token,
                    Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Entry* entry{Find(token)};
        if (!entry || !IsActive(entry->state)) return false;
        entry->state = State::COMPLETING;
        entry->updated_at = now;
        ++m_progress.verify_completed;
        return true;
    }

    /**
     * End an attempt without a terminal verdict. A retained body survives and
     * becomes retryable; otherwise the complete entry is removed.
     */
    bool Retry(const Token& token, Clock::duration delay,
               Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Entry* entry{Find(token)};
        if (!entry) return false;
        if (entry->state == State::RUNNING ||
            entry->state == State::AWAITING_QUORUM) {
            ++m_progress.verify_completed;
        }
        entry->pending_lease.reset();
        entry->cancelled.reset();
        entry->owned_resources.clear();
        // The worker has acknowledged (released the lease). If the block
        // connected while this replay was in flight (terminal_on_connect), do
        // NOT retain it for retry -- the hash is on the active chain; remove it
        // and release its retained-body accounting.
        if (!entry->body || entry->terminal_on_connect) {
            if (entry->body) {
                AccountSourceRemove(entry->body->source_netgroup,
                                    entry->body->bytes);
                m_retained_bytes -= entry->body->bytes;
            }
            m_entries.erase(token.hash);
            return true;
        }
        entry->body->retry_not_before = now + delay;
        entry->body->idle_retry_bypass_available = false;
        entry->state = State::TRANSIENT_FAILURE;
        entry->updated_at = now;
        return true;
    }

    /**
     * Release a live attempt that never received a body.
     *
     * GETMMATTEST / lifecycle Begin without Retain can leave
     * ADMISSION_PENDING with no body. FindNextBlocks must not treat that
     * VERIFY marker as a reason to skip DOWNLOAD. Attempts that already
     * retained a body are left alone (verify is actually in flight).
     *
     * @return true if a no-body active attempt was erased.
     */
    bool ExpireActiveWithoutBody(const uint256& hash,
                                 Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        (void)now;
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || !IsActive(it->second.state) ||
            it->second.body) {
            return false;
        }
        if (it->second.state == State::RUNNING ||
            it->second.state == State::AWAITING_QUORUM) {
            ++m_progress.verify_completed;
        }
        if (it->second.cancelled) {
            it->second.cancelled->store(true, std::memory_order_relaxed);
        }
        it->second.pending_lease.reset();
        it->second.cancelled.reset();
        it->second.owned_resources.clear();
        m_entries.erase(it);
        return true;
    }

    /**
     * Download-selector invariant: async-pending is a VERIFY state and must
     * never block DOWNLOAD of a body the node does not have.
     *
     * - have_data: skip while a live attempt remains (duplicate verify).
     * - !have_data: reclaim a no-body marker and do not skip; if a body was
     *   already retained the attempt stays live and fetch is skipped so a
     *   getdata/block busy loop cannot restart while ExactReplay is in flight.
     */
    bool ShouldSkipFetchWhileAsyncPending(
        const uint256& hash, bool have_data,
        Clock::time_point now = Clock::now())
    {
        if (have_data) return IsActive(hash, now);
        if (ExpireActiveWithoutBody(hash, now)) return false;
        return IsActive(hash, now);
    }

    /**
     * Compatibility cleanup for legacy state without a generation token.
     * It may postpone an inactive retained body, but can never mutate a live
     * generation: a delayed hash-only callback must not release a newer
     * attempt's slot, cancellation token, or source ownership.
     */
    bool RetryInactive(const uint256& hash, Clock::duration delay,
                       Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || IsActive(it->second.state)) return false;
        if (!it->second.body) {
            m_entries.erase(it);
            return true;
        }
        it->second.body->retry_not_before = now + delay;
        it->second.body->idle_retry_bypass_available = false;
        it->second.state = State::TRANSIENT_FAILURE;
        it->second.updated_at = now;
        return true;
    }

    /**
     * True when this hash still owns a retained body. Async-pending with a
     * body is a verify-in-flight state; without one it cannot be.
     */
    bool HasRetainedBody(const uint256& hash) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        return it != m_entries.end() && it->second.body.has_value();
    }

    // True if the retained body for `hash` is the followed tip-child / root
    // (pin_progress). Such a body is the productive catch-up root: when it
    // verifies it ConnectTips and is removed, so it can never spin. Callers use
    // this to retry it on a SHORT cadence instead of the ~60s budget-refill,
    // so it reclaims the single RC slot as soon as a band body frees it
    // (catch-up F1: without this a migrated node heals at <=1 block/min).
    bool IsRetainedPinProgress(const uint256& hash) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        return it != m_entries.end() && it->second.body.has_value() &&
               it->second.body->pin_progress;
    }

    /** Terminal acceptance/invalidity atomically releases every resource. */
    /** Clear only inactive retained state; never erase a live generation. */
    void TerminalRetained(const uint256& hash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it != m_entries.end() && !IsActive(it->second.state)) {
            EraseEntry(it);
        }
    }

    /**
     * Active-chain connection is terminal for every lifecycle generation.
     * Cancel live work and release the retained body so a late callback or
     * retry scan cannot re-admit an already-connected block.
     */
    void TerminalConnected(const uint256& hash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end()) return;
        if (IsActive(it->second.state)) {
            // DEPLOYMENT-BLOCKER fix (PR #132 review, jarekpiot): an active
            // entry may have a QUEUED or RUNNING full-body replay. EraseEntry
            // here would AccountSourceRemove / release the lease while the
            // worker still owns it -- and a RUNNING full-body replay bypasses
            // the cancel latch via ProtectsBodyReplay, so it keeps executing
            // against capacity already reported free. Instead: raise the cancel
            // latch (a header-only QUEUED job skips on dequeue; a full-body
            // QUEUED or RUNNING replay is ProtectsBodyReplay, so it runs to
            // completion), flag terminal-on-connect, and let the
            // worker-acknowledged Terminal()/Retry() erase it exactly once.
            // Capacity/resources stay owned until then; the connected hash is
            // never re-admitted (Retry erases instead of retaining).
            it->second.terminal_on_connect = true;
            if (it->second.cancelled) {
                it->second.cancelled->store(true, std::memory_order_relaxed);
            }
            return;
        }
        EraseEntry(it);
    }

    void Terminal(const Token& token)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(token.hash)};
        if (it != m_entries.end() &&
            it->second.generation == token.generation) {
            EraseEntry(it);
        }
    }

    std::optional<State> StateForTest(const uint256& hash) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end()) return std::nullopt;
        return it->second.state;
    }

    size_t RetainedCountForTest() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return RetainedCount();
    }

    size_t RetainedBytesForTest() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_retained_bytes;
    }

    size_t RetainedCountForSourceForTest(uint64_t netgroup) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return SourceCount(netgroup);
    }

private:
    struct Entry {
        State state{State::BODY_RETAINED};
        uint64_t generation{0};
        Clock::time_point updated_at{};
        std::optional<RetainedBody> body;
        std::shared_ptr<void> pending_lease;
        std::shared_ptr<std::atomic_bool> cancelled;
        std::vector<std::shared_ptr<void>> owned_resources;
        //! The block for this hash connected while a full-body replay may still
        //! be queued/running. We must NOT tear the entry down (that releases a
        //! lease/capacity the running worker still owns and a running replay
        //! bypasses the cancel latch via ProtectsBodyReplay); instead terminate
        //! it at the next worker-acknowledged transition (Terminal/Retry) and
        //! never re-admit the now-connected hash.
        bool terminal_on_connect{false};
    };

    using Map = std::map<uint256, Entry>;

    static bool IsActive(State state)
    {
        return state == State::ADMISSION_PENDING || state == State::QUEUED ||
               state == State::RUNNING || state == State::AWAITING_QUORUM ||
               state == State::COMPLETING;
    }

    uint64_t NextGeneration()
    {
        if (++m_next_generation == 0) ++m_next_generation;
        return m_next_generation;
    }

    Entry* Find(const Token& token)
    {
        const auto it{m_entries.find(token.hash)};
        if (it == m_entries.end() ||
            it->second.generation != token.generation) {
            return nullptr;
        }
        return &it->second;
    }

    void ExpireStaleAttempt(const uint256& hash, Clock::time_point now)
    {
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || !IsActive(it->second.state) ||
            now - it->second.updated_at <= m_async_stale_after) {
            return;
        }
        if (it->second.cancelled) {
            it->second.cancelled->store(true, std::memory_order_relaxed);
        }
        it->second.pending_lease.reset();
        it->second.cancelled.reset();
        it->second.owned_resources.clear();
        // See ExpireStaleAttempts: a terminal_on_connect entry is erased (with
        // accounting) rather than flipped to a retryable body.
        if (it->second.body && !it->second.terminal_on_connect) {
            it->second.state = State::TRANSIENT_FAILURE;
            it->second.updated_at = now;
        } else {
            EraseEntry(it);
        }
    }

    void PruneExpiredRetained(Clock::time_point now)
    {
        for (auto it = m_entries.begin(); it != m_entries.end();) {
            if (it->second.body && !IsActive(it->second.state) &&
                now - it->second.body->stored_at > m_retained_max_age) {
                auto victim{it++};
                EraseEntry(victim);
            } else {
                ++it;
            }
        }
        // Drop eviction tombstones past their TTL (same age bound as bodies).
        for (auto it = m_eviction_tombstones.begin();
             it != m_eviction_tombstones.end();) {
            if (now - it->second.tombstoned_at > m_retained_max_age) {
                it = m_eviction_tombstones.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t RetainedCount() const
    {
        return std::count_if(m_entries.begin(), m_entries.end(),
                             [](const auto& item) {
                                 return item.second.body.has_value();
                             });
    }

    Map::iterator OldestEvictable(const uint256& protected_hash)
    {
        auto oldest{m_entries.end()};
        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            if (it->first == protected_hash || !it->second.body ||
                IsActive(it->second.state) || it->second.body->pin_progress) {
                continue;
            }
            if (oldest == m_entries.end() ||
                it->second.body->stored_at < oldest->second.body->stored_at) {
                oldest = it;
            }
        }
        return oldest;
    }

    Map::iterator OldestEvictableForSource(const uint256& protected_hash,
                                           uint64_t netgroup)
    {
        auto oldest{m_entries.end()};
        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            if (it->first == protected_hash || !it->second.body ||
                IsActive(it->second.state) || it->second.body->pin_progress ||
                it->second.body->source_netgroup != netgroup) {
                continue;
            }
            if (oldest == m_entries.end() ||
                it->second.body->stored_at < oldest->second.body->stored_at) {
                oldest = it;
            }
        }
        return oldest;
    }

    size_t SourceCount(uint64_t netgroup) const
    {
        const auto it{m_retained_count_by_source.find(netgroup)};
        return it == m_retained_count_by_source.end() ? 0 : it->second;
    }

    size_t SourceBytes(uint64_t netgroup) const
    {
        const auto it{m_retained_bytes_by_source.find(netgroup)};
        return it == m_retained_bytes_by_source.end() ? 0 : it->second;
    }

    void AccountSourceAdd(uint64_t netgroup, size_t bytes)
    {
        m_retained_count_by_source[netgroup] += 1;
        m_retained_bytes_by_source[netgroup] += bytes;
    }

    void AccountSourceRemove(uint64_t netgroup, size_t bytes)
    {
        auto count_it{m_retained_count_by_source.find(netgroup)};
        if (count_it != m_retained_count_by_source.end()) {
            if (count_it->second <= 1) {
                m_retained_count_by_source.erase(count_it);
            } else {
                --count_it->second;
            }
        }
        auto bytes_it{m_retained_bytes_by_source.find(netgroup)};
        if (bytes_it != m_retained_bytes_by_source.end()) {
            if (bytes_it->second <= bytes) {
                m_retained_bytes_by_source.erase(bytes_it);
            } else {
                bytes_it->second -= bytes;
            }
        }
    }

    void EraseEntry(Map::iterator it)
    {
        if (it->second.cancelled) {
            it->second.cancelled->store(true, std::memory_order_relaxed);
        }
        if (it->second.body) {
            AccountSourceRemove(it->second.body->source_netgroup,
                                it->second.body->bytes);
            m_retained_bytes -= it->second.body->bytes;
        }
        m_entries.erase(it);
    }

    const size_t m_max_retained_count;
    const size_t m_max_retained_bytes;
    const size_t m_max_retained_count_per_source;
    const size_t m_max_retained_bytes_per_source;
    const Clock::duration m_retained_max_age;
    const Clock::duration m_async_stale_after;

    mutable std::mutex m_mutex;
    Map m_entries;
    // Eviction tombstones (cmpl-netdos F1): when a body is evicted under
    // CAPACITY pressure (not terminated), its freshness is remembered here so a
    // re-delivery of the same hash cannot reset stored_at / deferral_count / a
    // consumed idle bypass and thereby refresh the non-refreshing capacity TTL
    // (pinning attacker bodies and skewing oldest-first eviction against honest
    // ones). Bounded: pruned on the same m_retained_max_age as retained bodies
    // and capped at kMaxEvictionTombstones (oldest dropped).
    struct EvictionTombstone {
        Clock::time_point stored_at;
        uint32_t deferral_count{0};
        bool idle_retry_bypass_available{false};
        uint8_t retry_wake_mask{0};
        Clock::time_point tombstoned_at;
    };
    static constexpr size_t kMaxEvictionTombstones{4096};
    std::map<uint256, EvictionTombstone> m_eviction_tombstones;
    void RecordEvictionTombstone(Map::iterator victim, Clock::time_point now)
    {
        if (victim == m_entries.end() || !victim->second.body) return;
        if (m_eviction_tombstones.size() >= kMaxEvictionTombstones) {
            // Drop the oldest tombstone to stay bounded.
            auto oldest{m_eviction_tombstones.begin()};
            for (auto it = m_eviction_tombstones.begin();
                 it != m_eviction_tombstones.end(); ++it) {
                if (it->second.tombstoned_at < oldest->second.tombstoned_at) {
                    oldest = it;
                }
            }
            if (oldest != m_eviction_tombstones.end()) {
                m_eviction_tombstones.erase(oldest);
            }
        }
        m_eviction_tombstones[victim->first] = EvictionTombstone{
            victim->second.body->stored_at,
            victim->second.body->deferral_count,
            victim->second.body->idle_retry_bypass_available,
            victim->second.body->retry_wake_mask,
            now};
    }
    size_t m_retained_bytes{0};
    std::map<uint64_t, size_t> m_retained_count_by_source;
    std::map<uint64_t, size_t> m_retained_bytes_by_source;
    uint64_t m_next_generation{0};
    ProgressVector m_progress;
};

} // namespace node

#endif // BITCOIN_NODE_MATMUL_BLOCK_LIFECYCLE_H
