// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MATMUL_VERIFY_WORKER_H
#define BITCOIN_NODE_MATMUL_VERIFY_WORKER_H

#include <primitives/block.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace Consensus {
struct Params;
} // namespace Consensus

namespace node {

/** WP-7 / C5: bounded off-thread worker pool for the v4.4 ENC-DR O(W)
 *  reference recompute.
 *
 *  The single net message-handler thread holds g_msgproc_mutex across
 *  ProcessMessages -> ProcessBlock -> ... -> the ENC-DR recompute; cs_main is
 *  released around the recompute but g_msgproc_mutex is not, so every other
 *  peer's messages queue behind seconds of GEMM per non-cached block. This
 *  worker takes the PURE part of that work off the message thread:
 *
 *   - A Job carries the block, its resolved height (= prev->nHeight + 1),
 *     parent median-time-past (both resolved by the dispatcher under cs_main),
 *     and a completion closure. Parent MTP is required for Phase B seal-as-PoW
 *     sibling-slot V3 seeds; Classify only enqueues seal heights when MTP can
 *     be supplied, and the pure predicate fails closed without it.
 *   - The worker computes only the pure proof-of-work predicate (never
 *     touching cs_main or g_msgproc_mutex). Legacy ENC-DR uses the
 *     header-keyed MatMulRecomputeSingleFlight/verdict memo. Once Stage-3
 *     authority is enabled, its body proof bypasses both and uses the
 *     proof-aware (header, registry, payload) cache/single-flight owned by
 *     VerifyRCStage3ConsensusAttachment.
 *   - The completion (still on the worker thread) re-enters the ordinary
 *     acceptance machinery (ProcessNewBlock); the validation.cpp ENC-DR seam
 *     short-circuits on the memoized verdict, so the expensive step is not
 *     repeated.
 *
 *  Queue depth needs no separate bound: every enqueued job's closure owns a
 *  ScopedMatMulPendingVerification slot, so depth is bounded by the effective
 *  pending cap (nMatMulMaxPendingVerifications, or the LT seal tip-verify
 *  nMatMulLTMaxPendingVerifications when DRLT is live) by construction.
 *
 *  INACTIVITY INVARIANT: net_processing constructs this object only when
 *  nMatMulV4Height != INT32_MAX (and -matmulasyncverify is not disabled); with
 *  the fork disabled no instance ever exists and no thread is ever spawned. */
class MatMulVerifyWorker
{
public:
    /** Trusted mirrors wait for signatures rather than consuming a compute
     * lane. Bound that retained-body state independently from the expensive
     * replay queue so a missing signer cannot monopolize the default cap-one
     * RC verifier or turn full block deliveries into unbounded memory. */
    static constexpr size_t MAX_AWAITING_QUORUM_JOBS{16};
    static constexpr size_t MAX_AWAITING_QUORUM_BYTES{128U * 1024U * 1024U};

    enum class Priority : uint8_t {
        Background = 0,
        CompetingBranch = 1,
        AuthenticatedTipChild = 2,
    };

    enum class EnqueueMode : uint8_t {
        //! Add a new job, or join an existing non-cancelled same-hash job.
        JoinOrEnqueue,
        //! Header admission: never attach accounting to an existing job.
        NewOnly,
        //! Body join: never start unaccounted work if the header job vanished.
        JoinOnly,
    };

    enum class EnqueueResult : uint8_t {
        Enqueued,
        Joined,
        Deferred,
        Stopped,
    };

    enum class HandoffResult : uint8_t {
        HandedOff,
        Deferred,
        Stopped,
    };

    struct Job {
        std::shared_ptr<const CBlock> block;
        //! Height the block validates at (= prev->nHeight + 1), resolved by the
        //! dispatcher under cs_main before enqueueing.
        int32_t height{0};
        //! Parent median-time-past from prev under cs_main. Always set when the
        //! dispatcher classifies a recompute (prev is known). Phase B seal
        //! EncDr fails closed if missing.
        std::optional<int64_t> parent_median_time_past;
        //! Runs on the worker thread after verification (and after the
        //! applicable legacy or proof-aware memo is updated). May be empty.
        //! NOT run for jobs still queued when Stop() destroys the queue (their
        //! captured RAII state releases resources on destruction).
        std::function<void(bool encdr_ok)> completion;
        //! Runs only when RC verification produced no consensus verdict
        //! because the local accelerator failed or the replay was cancelled.
        //! Network callers use this to release async-delivery markers while
        //! leaving the block retryable; it must not punish a peer or pin a
        //! negative verdict.
        std::function<void()> retryable_failure;
        //! Expensive-lifecycle transition hooks. These are resource-owner
        //! callbacks, not observers: net_processing uses them to advance the
        //! generation that owns the retained body/cancel token/pending lease.
        std::function<void()> on_started;
        std::function<void()> on_parked;
        //! Header-only jobs begin digest-only ExactReplay while the body is
        //! still transferring/reconstructing. Exactly one of block/header is
        //! populated.
        std::shared_ptr<const CBlockHeader> header;
        Priority priority{Priority::Background};
        std::shared_ptr<std::atomic_bool> cancelled;
        //! One cap-one RC pending-work reservation. Header-first admission
        //! stores it outside `completion` so one bounded equal-priority
        //! handoff can transfer ownership without opening a second slot.
        std::shared_ptr<void> rc_pending_lease;
        //! Serialized full-body bytes retained while this job awaits quorum.
        //! Header-only jobs use zero. This is charged against the dedicated
        //! awaiting-quorum byte cap, not the compute pending-work cap.
        size_t retained_body_bytes{0};
        //! Header-only speculative quota/set ownership. Transferred to another
        //! header or released when the handoff target is a complete body.
        std::shared_ptr<void> rc_speculative_lease;
        //! Retarget the net-processing speculative-hash index on a
        //! header-to-header handoff.
        std::function<void(const uint256&)> retarget_speculative_lease;
        //! At most one equal-priority sibling may inherit this job's paid
        //! attempt. The replacement never receives another handoff.
        bool equal_priority_handoff_available{false};

        [[nodiscard]] const CBlockHeader& GetHeader() const
        {
            return block ? static_cast<const CBlockHeader&>(*block) : *header;
        }
        [[nodiscard]] bool IsHeaderOnly() const { return !block && header; }
    };

    /** @param[in] params       Consensus params (must outlive this object).
     *  @param[in] max_threads  Worker pool size; 0 = one device submitter.
     *                          More CPU threads do not increase throughput on
     *                          one saturated Metal GPU. Explicit values remain
     *                          available for CPU tests/non-Metal backends.
     *  @param[in] verify_for_test  Test-only seam replacing the pure predicate
     *                          (skips single-flight + verdict memo). Receives
     *                          the same (block, height, parent_mtp) the real
     *                          predicate would see. */
    explicit MatMulVerifyWorker(const Consensus::Params& params, uint32_t max_threads = 0,
                                std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> verify_for_test = nullptr);
    ~MatMulVerifyWorker(); // Stop() + join

    /** Try to enqueue or join a job. On Enqueued/Joined the job is moved-from.
     *  On Deferred/Stopped it is left intact. Deferred is deliberately
     *  distinct from shutdown: callers must never interpret a cancelled
     *  same-hash job or a failed JoinOnly as permission to run Q*-scale work
     *  synchronously on the P2P message thread. An authenticated-tip child
     *  preempts lower-priority in-flight speculation so a valid admission
     *  ticket cannot reserve the sole device lane indefinitely. Threads are
     *  started lazily. */
    EnqueueResult Enqueue(
        Job& job,
        EnqueueMode mode = EnqueueMode::JoinOrEnqueue);

    /** Atomically replace one paid authenticated-tip header-only attempt with
     *  an equal-priority sibling. The RC pending lease is transferred, never
     *  duplicated; a header replacement also inherits/retargets the
     *  speculative lease, while a complete body releases that header-only
     *  quota. Exactly one handoff is permitted for a paid attempt. */
    HandoffResult HandoffAuthenticatedTip(Job& replacement);
    [[nodiscard]] bool CanHandoffAuthenticatedTip(
        const CBlockHeader& replacement,
        int32_t height) const;

    /** Cancel queued/running speculative work for one header hash. */
    bool Cancel(const uint256& hash);

    /** Cancel every job selected by a tip/reorg-aware predicate. */
    size_t CancelIf(const std::function<bool(const CBlockHeader&, int32_t)>& predicate);
    [[nodiscard]] bool Contains(const uint256& hash) const;

    /** Publish the active tip so queued/parked trusted work ranks tip-first. */
    void SetActiveTip(const uint256& tip_hash, int32_t tip_height);

    /**
     * A parked trusted-mirror job may proceed: quorum is available for `hash`.
     * Never blocks; safe to call from the message thread without cs_main.
     */
    void NotifyQuorumReady(const uint256& hash);

    /** Stop accepting jobs; queued-not-started jobs receive retryable cleanup
     *  but no consensus completion; join in-flight jobs. Idempotent. */
    void Stop();

    //! Test introspection: current queued (not yet started) job count.
    size_t QueueDepthForTest() const;
    //! Test introspection: jobs parked awaiting an attestation quorum.
    size_t AwaitingQuorumForTest() const;

private:
    struct Pending {
        Job job;
        std::vector<std::function<void(bool)>> followers;
        std::vector<std::function<void()>> follower_retryable_failures;
        uint64_t sequence{0};
        bool running{false};
        //! Once a full block joins a header-first replay, tip churn may no
        //! longer cancel the shared computation and discard body validation.
        bool body_joined{false};
        //! When set, this job is parked awaiting attestation quorum and must
        //! not occupy a worker thread. Deadline is steady_clock.
        std::optional<std::chrono::steady_clock::time_point>
            awaiting_quorum_deadline{};
    };

    [[nodiscard]] bool HigherPriority(const Pending& lhs,
                                      const Pending& rhs) const;
    void WorkerLoop();
    /** Move expired/cancelled parked jobs out of the awaiting set. Caller
     *  invokes retryable callbacks WITHOUT holding m_mutex. */
    void TakeExpiredAwaitingQuorum(
        std::vector<std::shared_ptr<Pending>>& expired);
    [[nodiscard]] std::optional<std::chrono::steady_clock::time_point>
    NextAwaitingDeadline() const;
    void FinishRetryablePending(const std::shared_ptr<Pending>& pending);

    const Consensus::Params& m_params;
    const std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> m_verify_override;
    const uint32_t m_max_threads;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<std::shared_ptr<Pending>> m_queue; // GUARDED_BY(m_mutex)
    std::map<uint256, std::shared_ptr<Pending>> m_pending; // GUARDED_BY(m_mutex)
    //! Parked trusted-mirror jobs: waiting for M-of-N quorum without binding a
    //! worker thread. Still present in m_pending.
    std::map<uint256, std::shared_ptr<Pending>> m_awaiting_quorum; // GUARDED_BY(m_mutex)
    size_t m_awaiting_quorum_bytes{0}; // GUARDED_BY(m_mutex)
    uint256 m_tip_hash{}; // GUARDED_BY(m_mutex)
    int32_t m_tip_height{-1}; // GUARDED_BY(m_mutex)
    uint64_t m_next_sequence{0};          // GUARDED_BY(m_mutex)
    bool m_stopped{false};               // GUARDED_BY(m_mutex)
    std::vector<std::thread> m_threads;  // GUARDED_BY(m_mutex); lazily started on Enqueue
};

} // namespace node

#endif // BITCOIN_NODE_MATMUL_VERIFY_WORKER_H
