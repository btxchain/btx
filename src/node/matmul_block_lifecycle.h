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
                         Clock::duration async_stale_after)
        : m_max_retained_count{max_retained_count},
          m_max_retained_bytes{max_retained_bytes},
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
            if (it->second.body) {
                it->second.state = State::TRANSIENT_FAILURE;
                it->second.updated_at = now;
                ++it;
            } else {
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
        std::lock_guard<std::mutex> lock(m_mutex);
        PruneExpiredRetained(now);

        auto existing{m_entries.find(hash)};
        const size_t old_bytes{
            existing != m_entries.end() && existing->second.body
                ? existing->second.body->bytes
                : 0};
        const size_t old_count{old_bytes != 0 ? 1U : 0U};
        while (RetainedCount() - old_count + 1 > m_max_retained_count ||
               m_retained_bytes - old_bytes + body.bytes >
                   m_max_retained_bytes) {
            auto victim{OldestEvictable(hash)};
            if (victim == m_entries.end()) return false;
            EraseEntry(victim);
        }

        auto [it, inserted] = m_entries.try_emplace(hash);
        Entry& entry{it->second};
        const auto original_stored_at{
            entry.body ? entry.body->stored_at : now};
        if (entry.body) m_retained_bytes -= entry.body->bytes;
        // Capacity TTL is non-refreshing for a hash: retries or repeated
        // deliveries cannot pin retained bytes forever.
        body.stored_at = original_stored_at;
        entry.body = std::move(body);
        m_retained_bytes += entry.body->bytes;
        if (inserted || !IsActive(entry.state)) {
            entry.state = State::BODY_RETAINED;
            entry.updated_at = now;
        }
        return true;
    }

    std::optional<std::pair<uint256, RetainedBody>> NextRetry(
        const uint256& preferred_parent,
        Clock::time_point now = Clock::now(),
        bool ignore_retry_delay = false)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        PruneExpiredRetained(now);
        auto selected{m_entries.end()};
        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            const Entry& entry{it->second};
            if (!entry.body || IsActive(entry.state) ||
                (!ignore_retry_delay && now < entry.body->retry_not_before)) {
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
        return std::make_pair(selected->first, *selected->second.body);
    }

    /**
     * Select deferred catch-up work without allowing idle-mode urgency to
     * defeat an off-frontier retention cooldown.
     *
     * Ordinary idle catch-up may bypass retry delays to keep the verifier
     * occupied. Once the signed frontier is off the active chain, however,
     * those delays distinguish an ineligible losing fossil from the attested
     * sibling that can restore the frontier. Ignoring both delays lets the
     * lower-sorted fossil win every pass until its retention TTL expires.
     */
    std::optional<std::pair<uint256, RetainedBody>> NextDeferredCatchUpRetry(
        const uint256& preferred_parent,
        Clock::time_point now,
        bool idle_catchup,
        bool frontier_off_active_chain)
    {
        return NextRetry(
            preferred_parent, now,
            /*ignore_retry_delay=*/idle_catchup &&
                !frontier_off_active_chain);
    }

    bool RefreshRetry(const uint256& hash, Clock::duration delay,
                      Clock::time_point now = Clock::now())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_entries.find(hash)};
        if (it == m_entries.end() || !it->second.body) return false;
        it->second.body->retry_not_before = now + delay;
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
        if (!entry->body) {
            m_entries.erase(token.hash);
            return true;
        }
        entry->body->retry_not_before = now + delay;
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

private:
    struct Entry {
        State state{State::BODY_RETAINED};
        uint64_t generation{0};
        Clock::time_point updated_at{};
        std::optional<RetainedBody> body;
        std::shared_ptr<void> pending_lease;
        std::shared_ptr<std::atomic_bool> cancelled;
        std::vector<std::shared_ptr<void>> owned_resources;
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
        if (it->second.body) {
            it->second.state = State::TRANSIENT_FAILURE;
            it->second.updated_at = now;
        } else {
            m_entries.erase(it);
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
                IsActive(it->second.state)) {
                continue;
            }
            if (oldest == m_entries.end() ||
                it->second.body->stored_at < oldest->second.body->stored_at) {
                oldest = it;
            }
        }
        return oldest;
    }

    void EraseEntry(Map::iterator it)
    {
        if (it->second.cancelled) {
            it->second.cancelled->store(true, std::memory_order_relaxed);
        }
        if (it->second.body) {
            m_retained_bytes -= it->second.body->bytes;
        }
        m_entries.erase(it);
    }

    const size_t m_max_retained_count;
    const size_t m_max_retained_bytes;
    const Clock::duration m_retained_max_age;
    const Clock::duration m_async_stale_after;

    mutable std::mutex m_mutex;
    Map m_entries;
    size_t m_retained_bytes{0};
    uint64_t m_next_generation{0};
    ProgressVector m_progress;
};

} // namespace node

#endif // BITCOIN_NODE_MATMUL_BLOCK_LIFECYCLE_H
