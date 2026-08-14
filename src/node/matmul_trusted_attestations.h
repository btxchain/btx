// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H
#define BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H

#include <matmul/trusted_exact_replay_attestation.h>
#include <span.h>

#include <algorithm>
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
 * The in-memory hot cache remains capacity-bounded (defaults 4096 blocks /
 * 16384 signatures), while complete verified provenance is retained in a
 * disk-backed LevelDB and queried on cache misses. The legacy flat archive and
 * bounded WAL are migrated into that database. Every record is reverified
 * against the current configured chain/context/signers before use.
 */
bool OpenPersistence(const fs::path& path, std::string& error);
void ClosePersistence();
[[nodiscard]] bool PersistenceEnabled();
/** Synchronize queued records and checkpoint the bounded WAL (no-op if closed). */
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
 *
 * AuthorityAttestedFrontier() is the raw high-water mark (tests / diagnostics).
 * Production admit/park/header-request MUST run that mark through
 * SelectAuthorityAttestedFrontier so competing or unauthenticated heights —
 * including the parked miner fork — cannot raise the frontier above the
 * active tip chain or a short reorg (depth <= TRUSTED_MIRROR_SHORT_REORG_DEPTH).
 * Live 2026-08-13: raw frontier 187859 while the signer tip was 187791.
 */
static constexpr int TRUSTED_MIRROR_SHORT_REORG_DEPTH{6};
/** How far behind the active tip a node may GETMMATTEST so the attested
 *  tip is visible on a quiet linear chain (signer typically attests ~1
 *  behind). */
static constexpr int TRUSTED_MIRROR_ATTESTED_TIP_LOOKBACK{2};

/** LCA(tip, candidate) depth in (0, TRUSTED_MIRROR_SHORT_REORG_DEPTH].
 *  Depth 0 is the tip itself; depth 7+ is the EMERGENCY park window and the
 *  competing miner fork (live: ~200 headers at 1879xx vs a 187773 sibling). */
[[nodiscard]] inline bool TrustedMirrorIsShortTipReorg(int lca_depth)
{
    return lca_depth > 0 && lca_depth <= TRUSTED_MIRROR_SHORT_REORG_DEPTH;
}

/** FindMostWorkChain / candidate-set gate for any node that tracks a
 *  configured attestation quorum (trusted mirror, local signer, or
 *  consensus + -matmultrustedpubkey).
 *
 *  Tip-extending HAVE_DATA must always remain selectable: that is how the
 *  node catches up after a short reorg once the new parent is the tip.
 *  Selection is not the connect gate: TrustedMirrorMustDeferUnattestedConnect
 *  still refuses ConnectTip of an unattested Profile-1 block on a trusted
 *  mirror. A short attested tip-race (LCA depth 1–6 with quorum) may replace
 *  an *unattested* tip so a lost same-height sibling can converge.
 *
 *  Never reorg away a tip that already has quorum. Live 2026-08-13: the
 *  signer followed a heavier 4-block competing fork at 187795, signed it,
 *  and every mirror treated that as an attested short race. Competing
 *  then extended as "tip-extending" to 18781x.
 *
 *  A node already sitting on an unattested tip (equal-work lost sibling
 *  or heavier unattested fork) is recovered by
 *  FindUniqueCompetingAttestedIndex, not by this gate. */
[[nodiscard]] inline bool TrustedMirrorMaySelectMostWorkCandidate(
    bool extends_active_tip_chain,
    bool short_tip_reorg,
    bool has_quorum,
    bool active_tip_has_quorum = false)
{
    if (extends_active_tip_chain) return true;
    if (active_tip_has_quorum) return false;
    return short_tip_reorg && has_quorum;
}

/** ConnectTip / ActivateBestChainStep gate for a trusted Profile-1 node.
 *  Tip-extending HAVE_DATA stays selectable so a consensus signer can
 *  getdata an unattested tip-child (chicken-egg with archives). Quorum
 *  still gates activation: HAVE_DATA must not make an unattested MatMul
 *  block the active tip. */
[[nodiscard]] inline bool TrustedMirrorMustDeferUnattestedConnect(
    bool trusted_mirror_profile1,
    bool has_quorum)
{
    return trusted_mirror_profile1 && !has_quorum;
}

/** True when an alternate index may defer an unattested most-work candidate.
 *
 *  Qualifier 3ed2619c (PR 105): the active tip is always in
 *  setBlockIndexCandidates and is usually attested. Counting it — or any
 *  stale/non-distinct candidate-set entry — as an "attested sibling"
 *  permanently deferred the sole linear tip-child (behind=1, 83 repeats).
 *  Deferral is valid only for a distinct same-height child of the current
 *  tip that still has quorum and is not FAILED. Headers-only + quorum is
 *  usable (MMATTEST can land before the body); the tip itself is not. */
[[nodiscard]] inline bool TrustedMirrorAttestedSiblingIsActionable(
    bool distinct_from_candidate,
    bool same_parent,
    bool same_height_as_tip_child,
    bool has_quorum,
    bool failed = false)
{
    return distinct_from_candidate && same_parent &&
           same_height_as_tip_child && has_quorum && !failed;
}

/** FindMostWorkChain overlay for configured Profile-1 nodes (trusted
 *  mirrors and consensus miners with -matmultrustedpubkey).
 *
 *  Tip-children stay selectable (HAVE_DATA chicken-egg), but ConnectTip on
 *  a trusted mirror defers any unattested one. If that unattested child is
 *  also the heaviest candidate, ActivateBestChain stops on quorum Timeout
 *  and never tries an attested sibling already in the set. Live 2026-08-14
 *  fra1: tip 187931, attested a18786b0 at 187932, ABC looping 39c12144
 *  (unattested twin) so advertised seed height froze while the signer
 *  kept moving.
 *
 *  Defer the unattested most-work descendant only when
 *  TrustedMirrorAttestedSiblingIsActionable holds for some other index.
 *  Headers-only + quorum is enough: setBlockIndexCandidates is
 *  HAVE_DATA-gated, so the sibling may only be visible via
 *  AttestedFrontierHints / authenticated-candidate tips. FAILED indexes
 *  never block. If it is the only child, keep wait-for-quorum (mirror) or
 *  ExactReplay (consensus) behavior. FindUniqueCompetingAttestedIndex
 *  stays HAVE_DATA-gated (consensus miners switch on it after the fact). */
[[nodiscard]] inline bool TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
    bool configured_profile1,
    bool candidate_extends_tip,
    bool candidate_has_quorum,
    bool attested_tip_child_exists)
{
    return configured_profile1 && candidate_extends_tip &&
           !candidate_has_quorum && attested_tip_child_exists;
}

/** Height gap between the signed frontier (any stored quorum, including
 *  hashes this node has not fetched) and the highest quorum ancestor of
 *  the active tip. Zero on a healthy linear chain (signer ~1 behind the
 *  tip still yields 0: both sides sit at the last attested height). A
 *  stranded fork that never fetched the other chain's bodies still
 *  climbs this when MMATTEST arrives.
 *
 *  Qualifier 3ed2619c: this is 0 while a trusted mirror is stalled one
 *  HAVE_DATA child below the signer (active tip has quorum; the child
 *  does not). Do not treat blocks_behind==0 as "caught up to the
 *  network tip". */
[[nodiscard]] inline int32_t BlocksBehindSignedFrontier(
    int32_t signed_frontier_height,
    int32_t on_chain_attested_height)
{
    if (signed_frontier_height < 0 || on_chain_attested_height < 0) {
        return 0;
    }
    return std::max(0, signed_frontier_height - on_chain_attested_height);
}

/** Preferred GETMMATTEST work on a trusted mirror: the ActiveTip child, or
 *  the missing root of a short tip-race reorg (sibling of tip / first hole
 *  on the authority peer's best-known). Competing headers at 1879xx are
 *  neither. Parked deep-reorg branches never prefer. */
[[nodiscard]] inline bool TrustedMirrorPreferGetMmAttest(
    bool active_tip_child,
    bool short_tip_reorg_missing_root,
    bool on_parked_reorg_branch = false,
    bool recent_active_ancestor = false)
{
    if (on_parked_reorg_branch) return false;
    return active_tip_child || short_tip_reorg_missing_root ||
           recent_active_ancestor;
}

/** GETMMATTEST destinations. NODE_MATMUL_ATTESTATION_ARCHIVE is the signer.
 *  Trusted mirrors cache-and-forward signatures they have already accepted
 *  (they cannot SignAuthoritative). A recent valid MMATTEST is the same
 *  proof after the fact. Ordinary miners and nodes with no services still
 *  skip — they have no store. Direct signer addnode must not be required
 *  for functional mining. */
[[nodiscard]] inline bool PreferGetMmAttestPeer(
    bool has_attestation_archive_bit,
    bool recent_valid_mmattest,
    bool trusted_mirror = false)
{
    return has_attestation_archive_bit || recent_valid_mmattest ||
           trusted_mirror;
}

struct AttestedFrontierHint {
    uint256 hash{};
    int32_t height{-1};
};

[[nodiscard]] std::optional<int32_t> HighestAttestedHeight();
[[nodiscard]] std::optional<int32_t> AuthorityPeerTipHint();
[[nodiscard]] std::optional<uint256> AuthorityPeerTipHintHash();
[[nodiscard]] std::vector<AttestedFrontierHint> AttestedFrontierHints();
/** Raw high-water: max(highest attested, peer tip hint), if either known. */
[[nodiscard]] std::optional<int32_t> AuthorityAttestedFrontier();
void NoteAcceptedAttestationHeight(int32_t height, const uint256& hash = {});
void NoteAuthorityPeerTipHint(int32_t height, const uint256& hash = {});

/** Whether a frontier candidate may raise the effective attested frontier. */
struct AuthorityFrontierCandidateView {
    bool on_or_extends_active_tip_chain{false};
    bool short_tip_reorg{false};
    bool on_parked_reorg_branch{false};
};

[[nodiscard]] inline bool AuthorityFrontierCandidateUsable(
    const AuthorityFrontierCandidateView& v)
{
    if (v.on_parked_reorg_branch) return false;
    return v.on_or_extends_active_tip_chain || v.short_tip_reorg;
}

/** Pick the highest usable attested height / peer-tip hint. Unusable
 *  competing or parked heights are ignored rather than mixed into max(). */
[[nodiscard]] inline std::optional<int32_t> SelectAuthorityAttestedFrontier(
    std::optional<int32_t> attested_height,
    bool attested_usable,
    std::optional<int32_t> peer_tip_hint,
    bool hint_usable)
{
    std::optional<int32_t> out;
    if (attested_usable && attested_height.has_value() &&
        *attested_height >= 0) {
        out = attested_height;
    }
    if (hint_usable && peer_tip_hint.has_value() && *peer_tip_hint >= 0) {
        out = out.has_value() ? std::max(*out, *peer_tip_hint) : peer_tip_hint;
    }
    return out;
}

/**
 * Pure admission policy for trusted-mirror attestation / park / verify slots.
 *
 * Tip-extending work is always eligible (except cancelled/stopped paths): it is
 * how the mirror advances, and may briefly probe one height past a stale
 * frontier so the frontier can catch up when the authority mines. A short tip
 * reorg (LCA depth 1–TRUSTED_MIRROR_SHORT_REORG_DEPTH) is first-class like
 * tip-extending: it must not be starved by competing getmmattest slots,
 * signer-absent backoff, or RejectNotForwardOfTip. Park is evaluated first
 * for that path and is never bypassed. Everything else must be a forward
 * extension of the active tip's chain or lie on the exact branch selected by
 * shared shallow-recovery state, must not sit on a parked deep-reorg branch,
 * must not exceed the known authority frontier, and must not be in
 * negative-cache backoff after signers stayed silent.
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
    //! LCA(tip, candidate) depth in (0, TRUSTED_MIRROR_SHORT_REORG_DEPTH].
    //! Same-height sibling / short fork of the authenticated tip. First-class
    //! like tip_extending for GETMMATTEST slots, but park still wins.
    bool short_tip_reorg{false};
    //! index->GetAncestor(tip_height) == tip (strict forward of active tip).
    bool extends_active_tip_chain{false};
    //! Branch carries strictly more work than the active tip, i.e. this is a
    //! genuine reorg candidate rather than sibling noise. A mirror that lands on
    //! a losing sibling (same height, different hash) has an active tip that
    //! NOTHING on the winning branch extends, so without this the forward-of-tip
    //! rule rejects every block that could rescue it and the mirror is stuck
    //! until an operator runs invalidateblock. Observed in production: a mirror
    //! sat on a 1-block sibling fork at 186355 while the authority ran 23 blocks
    //! ahead, requesting nothing. Deep-reorg refusal stays with the park policy,
    //! which is evaluated separately and still wins.
    bool better_work_reorg_candidate{false};
    //! Candidate lies on the exact branch selected by shared recovery state.
    //! Roots of that branch may temporarily carry less work than a losing
    //! active tip and still must be admitted so their descendants can connect.
    bool on_recovery_branch{false};
    //! Active tip or an ancestor within TRUSTED_MIRROR_ATTESTED_TIP_LOOKBACK.
    //! Linear-chain GETMMATTEST so getmatmulattestedtip is populated without
    //! waiting for a race. Park still wins.
    bool on_recent_active_ancestor{false};
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
    if (v.short_tip_reorg || v.on_recent_active_ancestor) {
        // Short tip-race reorg, or the active tip / last few ancestors so a
        // linear chain can populate getmatmulattestedtip. Park still wins.
        return TrustedAttestationAdmit::Allow;
    }
    // A better-work branch is admissible even though it does not extend our
    // active tip -- that is precisely what a reorg looks like. Refusing it here
    // would make a mirror that lost a same-height race unable to ever fetch the
    // winning branch. Depth is not this rule's concern: on_parked_reorg_branch
    // above already refused anything the park policy declined.
    if (!v.extends_active_tip_chain && !v.better_work_reorg_candidate &&
        !v.on_recovery_branch) {
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

/** Result of applying the independent tip-extender occupancy ceiling. */
struct TipExtendingCapacityDecision {
    bool allow{false};
    std::optional<size_t> replace_index{};
};

/** Bound free Phase-1 siblings that all claim to extend the active tip. */
[[nodiscard]] inline TipExtendingCapacityDecision EvaluateTipExtendingCapacity(
    const TrustedWorkRank& candidate,
    Span<const TrustedWorkRank> current,
    size_t max_tip_extending)
{
    if (max_tip_extending == 0) return {};
    if (current.size() < max_tip_extending) return {.allow = true};
    size_t worst{0};
    for (size_t i{1}; i < current.size(); ++i) {
        if (PreferTrustedWork(current[worst], current[i])) worst = i;
    }
    if (!PreferTrustedWork(candidate, current[worst])) return {};
    return {.allow = true, .replace_index = worst};
}

/**
 * Trusted-mirror best-header policy (sync only, not consensus).
 *
 * PreferTrustAdjustedHeader now carries a bounded unauth allowance so any
 * node (including consensus) can chase a short competing headers-only branch
 * after a lost race. Trusted mirrors still need this tip-chain / authority
 * overlay: (1) ordinary non-authority competing forks must not displace
 * m_best_header with unattestable spam, (2) authority peers may follow a
 * better-or-equal-work reorg candidate even when it sits beyond the global
 * allowance or the tip-pinned best-header would otherwise stall getheaders,
 * and (3) parked deep-reorg branches stay excluded. This does not accept
 * blocks; M-of-N quorum remains required.
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
    if (v.on_parked_reorg_branch) {
        return false;
    }
    if (!v.extends_active_tip_chain) {
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
 * Authority-scoped header-frontier policy for trusted mirrors.
 *
 * Tip-chain extensions behave like PreferTrustedMirrorTipChainHeader.
 * Additionally, when the header came from an attestation-authority peer, a
 * better-or-equal-work branch that does not extend the (losing) tip may
 * displace m_best_header so getheaders / download chase the authority's
 * chain. Park policy is evaluated first and is never bypassed.
 */
struct TrustedMirrorAuthorityHeaderView {
    bool from_authority_peer{false};
    bool extends_active_tip_chain{false};
    //! Candidate carries >= tip work and is not the tip itself (equal-work
    //! sibling or heavier fork).
    bool better_work_reorg_candidate{false};
    bool on_parked_reorg_branch{false};
    //! LCA(tip, candidate) depth in (0, TRUSTED_MIRROR_SHORT_REORG_DEPTH].
    //! An authority short-reorg must displace a best-header that sits on the
    //! claimed-heaviest miner fork (live: m_best_header 187978 vs signer 187791).
    bool short_tip_reorg{false};
    int32_t candidate_height{-1};
    int32_t tip_height{-1};
    int32_t current_best_height{-1};
    bool current_best_extends_tip{false};
    bool candidate_extends_current_best{false};
};

/** A peer's recent valid signature is branch-bound provenance, not a bearer
 * capability. It may steer only descendants of the exact attested block. */
[[nodiscard]] inline bool AuthorityProofCoversCandidate(
    bool proof_recent, bool proof_index_known, int32_t proof_height,
    int32_t candidate_height, bool candidate_descends_proof,
    bool proof_not_behind_active_tip = true,
    bool authority_context_matches = true)
{
    return proof_recent && proof_index_known && proof_height >= 0 &&
        candidate_height >= proof_height && candidate_descends_proof &&
        proof_not_behind_active_tip && authority_context_matches;
}

[[nodiscard]] inline bool PreferTrustedMirrorAuthorityHeader(
    const TrustedMirrorAuthorityHeaderView& v)
{
    if (!v.from_authority_peer) {
        return PreferTrustedMirrorTipChainHeader({
            .extends_active_tip_chain = v.extends_active_tip_chain,
            .on_parked_reorg_branch = v.on_parked_reorg_branch,
            .candidate_height = v.candidate_height,
            .tip_height = v.tip_height,
            .current_best_height = v.current_best_height,
            .current_best_extends_tip = v.current_best_extends_tip,
            .candidate_extends_current_best = v.candidate_extends_current_best,
        });
    }
    if (v.on_parked_reorg_branch) {
        return false;
    }
    if (v.extends_active_tip_chain) {
        return PreferTrustedMirrorTipChainHeader({
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .candidate_height = v.candidate_height,
            .tip_height = v.tip_height,
            .current_best_height = v.current_best_height,
            .current_best_extends_tip = v.current_best_extends_tip,
            .candidate_extends_current_best = v.candidate_extends_current_best,
        });
    }
    // Authority competing branch: only follow better/equal work, never a
    // lighter fork, and never below tip height (no rewind via headers alone).
    if (!v.better_work_reorg_candidate) {
        return false;
    }
    if (v.candidate_height < v.tip_height) {
        return false;
    }
    // Authority short-reorg displaces a best-header that is not on the active
    // tip chain — including a *taller* claimed-heaviest miner fork. Height
    // comparison against that fork would pin m_best_header there forever
    // (live: 187978 competing vs signer 187791) and starve sibling download.
    if (v.short_tip_reorg && !v.current_best_extends_tip) {
        if (v.candidate_extends_current_best) {
            return v.candidate_height > v.current_best_height;
        }
        return true;
    }
    // Tip-pinned losing best-header must be displaced so headers advance off
    // the stranded tip. This is the production stall (headers==blocks while
    // the authority is hundreds of blocks ahead on the other sibling).
    if (v.current_best_extends_tip) {
        return true;
    }
    // Already following a non-tip branch: grow along it, or jump to a taller
    // authority header on another equal/better-work fork.
    if (v.candidate_extends_current_best) {
        return v.candidate_height > v.current_best_height;
    }
    return v.candidate_height >= v.current_best_height;
}

/**
 * Whether a peer's best-known tip lies on the best-header chain the mirror
 * already follows (ancestor of, or extension of, m_best_header).
 *
 * Used to widen competing-branch *download* to any peer that has the recovery
 * chain after authority header-follow selected it. Fetching is not trusting;
 * acceptance still requires M-of-N. Random competing forks that never became
 * m_best_header cannot qualify, preserving the fra1 inflight-DoS bound.
 */
[[nodiscard]] inline bool TrustedMirrorOnFollowedHeaderChain(
    bool best_header_known,
    bool peer_best_is_ancestor_of_best_header,
    bool peer_best_extends_best_header)
{
    if (!best_header_known) {
        return false;
    }
    return peer_best_is_ancestor_of_best_header ||
           peer_best_extends_best_header;
}

/**
 * Whether a trusted mirror may download / direct-fetch toward a peer's
 * best-known tip that does not extend the active tip.
 *
 * Parked deep-reorg branches: never.
 * Better/equal CLAIMED work (nChainWork, not trust-adjusted) competing branch:
 * yes from an attestation-authority peer, OR from any peer whose best-known
 * lies on the already-followed best-header chain (authority-selected recovery
 * path). Callers must pass claimed-work comparisons for better_or_equal_work —
 * trust-adjusted work is for preference/acceptance only; gating download on it
 * deadlocks when a headers-only suffix is deeper than the unauth allowance.
 * Depending on a single authority connection left mirrors stranded when that
 * peer's inflight slots were full or silent while many ordinary peers held the
 * identical recovery bodies.
 *
 * `on_followed_best_header_chain` is accepted for call-site compatibility but
 * MUST NOT open the download gate by itself. Production m_best_header tracks
 * claimed-heaviest headers, which is the competing miner fork (~hundreds
 * ahead). Treating that as "followed" made mirrors fetch the parked heavy
 * branch and skip the authority's same-height sibling (live 187773 race).
 * A short tip reorg (LCA depth 1–park) is the recovery that actually
 * unsticks a mirror that lost a 1-block race.
 */
[[nodiscard]] inline bool TrustedMirrorMayDownloadCompetingBranch(
    bool is_authority_peer,
    bool best_known_extends_tip,
    bool better_or_equal_work,
    bool on_parked_reorg_branch,
    bool on_followed_best_header_chain = false,
    bool short_tip_reorg = false)
{
    (void)on_followed_best_header_chain;
    if (best_known_extends_tip) {
        return true;
    }
    if (on_parked_reorg_branch) {
        return false;
    }
    if (!better_or_equal_work) {
        return false;
    }
    return is_authority_peer || short_tip_reorg;
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
