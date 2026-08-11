// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H
#define BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H

#include <matmul/trusted_exact_replay_attestation.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <uint256.h>
#include <util/fs.h>

namespace node::matmul_trusted {

/** Process-local operator trust runtime.
 *
 * The core attestation store is consensus-neutral. This adapter records the
 * explicit node role and is the sole seam used by validation, P2P, and RPC.
 * Configure once during startup, before any validation worker is created.
 */
bool Configure(matmul::trusted::StoreConfig config,
               bool trusted_mirror,
               bool serve_attestations,
               std::chrono::milliseconds wait_timeout,
               std::string& error);
/**
 * Stage startup configuration before the process signing context exists.
 *
 * AppInitParameterInteraction runs before ECC_Context is constructed, so it
 * must not derive the local signer's public key. FinalizeConfiguration must be
 * called from AppInitMain after ECC initialization and before networking or
 * validation starts.
 */
bool StageConfiguration(matmul::trusted::StoreConfig config,
                        std::optional<std::string> local_signer_wif,
                        bool trusted_mirror,
                        bool serve_attestations,
                        std::chrono::milliseconds wait_timeout,
                        std::string& error);
bool FinalizeConfiguration(std::string& error);
void Reset();
void ResetForTest();

[[nodiscard]] bool IsConfigured();
[[nodiscard]] bool IsTrustedMirror();
[[nodiscard]] bool ServesAttestations();
[[nodiscard]] bool HasLocalSigner();
[[nodiscard]] std::chrono::milliseconds WaitTimeout();
[[nodiscard]] size_t Threshold();
[[nodiscard]] std::vector<CPubKey> TrustedSigners();
[[nodiscard]] std::optional<CPubKey> LocalSigner();
[[nodiscard]] std::optional<uint256> ReplayAuthorityContext();

[[nodiscard]] matmul::trusted::AddResult Add(
    const matmul::trusted::ExactReplayAttestation& attestation,
    const uint256& expected_hash,
    int32_t expected_height);
[[nodiscard]] matmul::trusted::AddResult SignAuthoritative(
    const uint256& block_hash,
    int32_t block_height,
    matmul::trusted::ExactReplayAttestation* produced = nullptr);
/**
 * Sign a UTXO snapshot statement with the configured local attestation key.
 * Returns nullopt when unconfigured or the statement's chain/authority fields
 * do not match the local trusted-mirror configuration.
 */
[[nodiscard]] std::optional<matmul::trusted::UtxoSnapshotSignature>
SignUtxoSnapshot(const matmul::trusted::UtxoSnapshotStatement& statement);
/**
 * Verify an attested-fast-forward manifest against the configured signer set
 * and threshold. Consensus nodes (no store) always fail closed.
 */
[[nodiscard]] matmul::trusted::UtxoSnapshotVerifyResult
VerifyUtxoSnapshotManifest(
    const matmul::trusted::UtxoSnapshotManifest& manifest);
[[nodiscard]] std::optional<uint256> ChainId();
[[nodiscard]] bool HasQuorum(const uint256& block_hash, int32_t block_height);
/**
 * Blocking wait retained for tests and rare sync callers. Trusted-mirror
 * verify workers must NOT use this on the hot path: they park the job and
 * continue so other blocks stay in flight (see MatMulVerifyWorker).
 */
[[nodiscard]] matmul::trusted::WaitResult WaitForQuorum(
    const uint256& block_hash,
    int32_t block_height,
    const std::function<bool()>& cancelled,
    std::vector<matmul::trusted::ExactReplayAttestation>* quorum = nullptr);
[[nodiscard]] std::vector<matmul::trusted::ExactReplayAttestation> Get(
    const uint256& block_hash, int32_t block_height);
[[nodiscard]] matmul::trusted::StoreStats Stats();

/**
 * Open/replace the durable attestation archive under `path`.
 *
 * Retention: capacity-bounded to the store's max_blocks/max_attestations
 * (defaults 4096 blocks / 16384 signatures). Wall-clock TTL pruning is
 * disabled while the archive is open so a long-lived authority process cannot
 * drop signatures that mirrors still need after a restart. Oldest completed
 * buckets are still evicted under capacity pressure. Load verifies every
 * signature against the current configured chain/signers before import.
 */
bool OpenPersistence(const fs::path& path, std::string& error);
void ClosePersistence();
[[nodiscard]] bool PersistenceEnabled();
/** Flush the in-memory store to the durable archive (no-op if closed). */
bool FlushPersistence(std::string& error);

/**
 * Historical ExactReplay re-verify budget (authority serve path).
 *
 * Unauthenticated peers already pay a GETMMATTEST token; this second budget
 * bounds expensive GPU ExactReplay so a flood of requests for blocks lacking a
 * persisted ExactReplay bit cannot monopolize the device. Defaults: burst 2,
 * refill one token / 30s, max 4 queued, max 1 in flight.
 */
struct HistoricalReverifyBudget {
    static constexpr double BURST{2.0};
    static constexpr auto REFILL{std::chrono::seconds{30}};
    static constexpr size_t QUEUE_MAX{4};
    static constexpr size_t INFLIGHT_MAX{1};
};

enum class HistoricalReverifyAdmit : uint8_t {
    Allow,
    RateLimited,
    QueueFull,
    AlreadyQueued,
    InflightFull,
};

[[nodiscard]] HistoricalReverifyAdmit TryAdmitHistoricalReverify(
    const uint256& block_hash);
void NoteHistoricalReverifyStarted(const uint256& block_hash);
void NoteHistoricalReverifyFinished(const uint256& block_hash);
void ResetHistoricalReverifyBudgetForTest();
[[nodiscard]] size_t HistoricalReverifyQueuedForTest();
[[nodiscard]] size_t HistoricalReverifyInflightForTest();

/**
 * Local sync-policy hints for a trusted mirror (not consensus).
 *
 * The attested frontier is the highest height for which this process has seen a
 * cryptographically valid attestation from a configured signer. Optionally, a
 * soft peer-tip hint records the best-known height of peers that recently
 * delivered usable MMATTEST. Neither field lowers the M-of-N quorum; they only
 * decide which blocks may consume scarce request/park/verify slots.
 */
[[nodiscard]] std::optional<int32_t> HighestAttestedHeight();
[[nodiscard]] std::optional<int32_t> AuthorityPeerTipHint();
/** Effective frontier: max(highest attested, peer tip hint), if either known. */
[[nodiscard]] std::optional<int32_t> AuthorityAttestedFrontier();
void NoteAcceptedAttestationHeight(int32_t height);
void NoteAuthorityPeerTipHint(int32_t height);

/**
 * Pure admission policy for trusted-mirror attestation / park / verify slots.
 *
 * Tip-extending work is always eligible (except cancelled/stopped paths): it is
 * how the mirror advances, and may briefly probe one height past a stale
 * frontier so the frontier can catch up when the authority mines. Everything
 * else must be a forward extension of the active tip's chain, must not sit on a
 * parked deep-reorg branch, must not exceed the known authority frontier, and
 * must not be in negative-cache backoff after signers stayed silent.
 */
enum class TrustedAttestationAdmit : uint8_t {
    Allow,
    RejectNotForwardOfTip,
    RejectParkedReorg,
    RejectAboveFrontier,
    RejectBackoff,
};

struct TrustedAttestationAdmitView {
    bool tip_extending{false};
    //! index->GetAncestor(tip_height) == tip (strict forward of active tip).
    bool extends_active_tip_chain{false};
    bool on_parked_reorg_branch{false};
    int32_t height{-1};
    std::optional<int32_t> authority_frontier{};
    bool in_backoff{false};
};

[[nodiscard]] inline TrustedAttestationAdmit EvaluateTrustedAttestationAdmit(
    const TrustedAttestationAdmitView& v)
{
    if (v.tip_extending) {
        // Tip-extender is never starved by frontier/backoff/branch filters.
        return TrustedAttestationAdmit::Allow;
    }
    if (v.on_parked_reorg_branch) {
        return TrustedAttestationAdmit::RejectParkedReorg;
    }
    if (!v.extends_active_tip_chain) {
        return TrustedAttestationAdmit::RejectNotForwardOfTip;
    }
    if (v.authority_frontier.has_value() &&
        v.height > *v.authority_frontier) {
        return TrustedAttestationAdmit::RejectAboveFrontier;
    }
    if (v.in_backoff) {
        return TrustedAttestationAdmit::RejectBackoff;
    }
    return TrustedAttestationAdmit::Allow;
}

[[nodiscard]] inline const char* TrustedAttestationAdmitName(
    TrustedAttestationAdmit decision)
{
    switch (decision) {
    case TrustedAttestationAdmit::Allow:
        return "allow";
    case TrustedAttestationAdmit::RejectNotForwardOfTip:
        return "reject_not_forward_of_tip";
    case TrustedAttestationAdmit::RejectParkedReorg:
        return "reject_parked_reorg";
    case TrustedAttestationAdmit::RejectAboveFrontier:
        return "reject_above_frontier";
    case TrustedAttestationAdmit::RejectBackoff:
        return "reject_backoff";
    }
    return "unknown";
}

/**
 * Outstanding-request capacity under tip reservation.
 *
 * Non-tip work may only fill `max_outstanding - tip_reserved` slots so a
 * tip-extender can always admit (binding tip-first under slot pressure). Tip
 * work itself is always permitted to attempt admission (and may displace
 * non-tip occupants when the map is completely full).
 */
[[nodiscard]] inline bool TrustedAttestationRequestCapacityAllows(
    bool tip_extending,
    size_t outstanding,
    size_t max_outstanding,
    size_t tip_reserved = 1)
{
    if (max_outstanding == 0) return false;
    if (tip_reserved > max_outstanding) tip_reserved = max_outstanding;
    if (tip_extending) return true;
    return outstanding < max_outstanding - tip_reserved;
}

/**
 * Tip-first ranking for trusted-mirror attestation / verify work.
 *
 * Prefer the block that extends the active tip, then blocks above the tip in
 * ascending height (build toward the best header), and never let already-
 * connected / below-tip backfill starve tip advancement. `priority_rank` is the
 * MatMulVerifyWorker::Priority ordinal when applicable (higher is better); use
 * 0 when ranking request slots alone. Lower `sequence` wins ties (FIFO).
 */
struct TrustedWorkRank {
    bool tip_extending{false};
    bool above_tip{false};
    uint8_t priority_rank{0};
    int32_t height{0};
    uint64_t sequence{0};
};

[[nodiscard]] inline bool PreferTrustedWork(const TrustedWorkRank& a,
                                            const TrustedWorkRank& b)
{
    if (a.tip_extending != b.tip_extending) return a.tip_extending;
    if (a.above_tip != b.above_tip) return a.above_tip;
    if (a.priority_rank != b.priority_rank) {
        return a.priority_rank > b.priority_rank;
    }
    if (a.above_tip && b.above_tip && a.height != b.height) {
        // Ascending from the tip toward the best header.
        return a.height < b.height;
    }
    if (!a.above_tip && !b.above_tip && a.height != b.height) {
        // Backfill last; among it, prefer higher (closer to tip) first.
        return a.height > b.height;
    }
    return a.sequence < b.sequence;
}

[[nodiscard]] inline TrustedWorkRank MakeTrustedWorkRank(
    bool tip_extending,
    int32_t height,
    int32_t tip_height,
    uint8_t priority_rank = 0,
    uint64_t sequence = 0)
{
    return TrustedWorkRank{
        .tip_extending = tip_extending,
        .above_tip = height > tip_height,
        .priority_rank = priority_rank,
        .height = height,
        .sequence = sequence,
    };
}

/**
 * Trusted-mirror best-header policy (sync only, not consensus).
 *
 * PreferTrustAdjustedHeader intentionally pins m_best_header to authenticated
 * work so an unverified MatMul header cannot displace its parent. Trusted
 * mirrors still need the header frontier that extends the active tip so they
 * can request the next body from the attestation authority. Competing forks
 * never satisfy `extends_active_tip_chain`. Parked deep-reorg branches are
 * excluded. This does not accept blocks; M-of-N quorum remains required.
 */
struct TrustedMirrorTipChainHeaderView {
    bool extends_active_tip_chain{false};
    bool on_parked_reorg_branch{false};
    int32_t candidate_height{-1};
    int32_t tip_height{-1};
    int32_t current_best_height{-1};
    //! True when the current m_best_header itself extends the active tip.
    bool current_best_extends_tip{false};
    //! True when candidate is a descendant of the current best header.
    bool candidate_extends_current_best{false};
};

[[nodiscard]] inline bool PreferTrustedMirrorTipChainHeader(
    const TrustedMirrorTipChainHeaderView& v)
{
    if (!v.extends_active_tip_chain || v.on_parked_reorg_branch) {
        return false;
    }
    if (v.candidate_height <= v.tip_height) {
        return false;
    }
    // Displace a best-header that is not on the tip chain (stale / competing).
    if (!v.current_best_extends_tip) {
        return true;
    }
    // Grow along the tip-chain frontier.
    return v.candidate_extends_current_best &&
           v.candidate_height > v.current_best_height;
}

/**
 * Sticky unattestable-reject accounting: count a hash only when it is newly
 * entered into the negative cache (or its sticky window has expired and it is
 * being re-armed). Repeat evaluations inside the window must not increment.
 */
struct TrustedRejectStickyView {
    bool already_cached{false};
    bool window_active{false};
};

[[nodiscard]] inline bool CountTrustedRejectAsDistinct(
    const TrustedRejectStickyView& v)
{
    if (!v.already_cached) return true;
    return !v.window_active;
}

} // namespace node::matmul_trusted

#endif // BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H
