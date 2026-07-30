// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MATMUL_VERIFY_WORKER_H
#define BITCOIN_NODE_MATMUL_VERIFY_WORKER_H

#include <primitives/block.h>

#include <atomic>
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
    enum class Priority : uint8_t {
        Background = 0,
        CompetingBranch = 1,
        AuthenticatedTipChild = 2,
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
        //! Header-only jobs begin digest-only ExactReplay while the body is
        //! still transferring/reconstructing. Exactly one of block/header is
        //! populated.
        std::shared_ptr<const CBlockHeader> header;
        Priority priority{Priority::Background};
        std::shared_ptr<std::atomic_bool> cancelled;

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

    /** Try to enqueue a job. On success the job is moved-from and true is
     *  returned. On failure (worker stopped) the job is LEFT INTACT and false
     *  is returned — the caller must fall back to the synchronous path (e.g.
     *  by invoking the completion itself). Threads are started lazily. */
    bool Enqueue(Job& job);

    /** Cancel queued/running speculative work for one header hash. */
    bool Cancel(const uint256& hash);

    /** Cancel every job selected by a tip/reorg-aware predicate. */
    size_t CancelIf(const std::function<bool(const CBlockHeader&, int32_t)>& predicate);
    [[nodiscard]] bool Contains(const uint256& hash) const;

    /** Stop accepting jobs; DESTROY queued-not-started jobs WITHOUT running
     *  their completions (RAII captured inside the closures releases slots);
     *  join in-flight jobs. Idempotent. */
    void Stop();

    //! Test introspection: current queued (not yet started) job count.
    size_t QueueDepthForTest() const;

private:
    struct Pending {
        Job job;
        std::vector<std::function<void(bool)>> followers;
        uint64_t sequence{0};
        bool running{false};
        //! Once a full block joins a header-first replay, tip churn may no
        //! longer cancel the shared computation and discard body validation.
        bool body_joined{false};
    };

    [[nodiscard]] static bool HigherPriority(const Pending& lhs, const Pending& rhs);
    void WorkerLoop();

    const Consensus::Params& m_params;
    const std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> m_verify_override;
    const uint32_t m_max_threads;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<std::shared_ptr<Pending>> m_queue; // GUARDED_BY(m_mutex)
    std::map<uint256, std::shared_ptr<Pending>> m_pending; // GUARDED_BY(m_mutex)
    uint64_t m_next_sequence{0};          // GUARDED_BY(m_mutex)
    bool m_stopped{false};               // GUARDED_BY(m_mutex)
    std::vector<std::thread> m_threads;  // GUARDED_BY(m_mutex); lazily started on Enqueue
};

} // namespace node

#endif // BITCOIN_NODE_MATMUL_VERIFY_WORKER_H
