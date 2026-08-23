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
#include <limits>
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
/** In-memory store only. FindMostWorkChain must not durable-read+verify
 *  every candidate under cs_main (live archive RPC wedge: ~45s/ABC). */
[[nodiscard]] bool HasQuorumInMemory(const uint256& block_hash,
                                     int32_t block_height);
/** True when a different hash at this height already has in-memory quorum
 *  (frontier hints). Must not durable-read under cs_main. */
[[nodiscard]] bool HasCompetingQuorum(const uint256& block_hash,
                                      int32_t block_height);
/** True when this process already signed a different hash at this height.
 *  In-memory map from durable load and local Sign; no LevelDB read. */
[[nodiscard]] bool HasLocalSignatureAtHeight(const uint256& block_hash,
                                             int32_t block_height);
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
/** Local signers serve GETMMATTEST only inside this live window (tip-N).
 *  Historical scans belong on archives. Hammering a signer with old
 *  hashes is ignored, then banned. */
static constexpr int SIGNER_GETMMATTEST_SERVE_WINDOW{16};
/** Cached catch-up GETMMATTEST, beyond the live window, only this far
 *  behind the signer tip. Live 2026-08-16: after opening cached serve to
 *  every addnode/manual peer, IBD nodes at ~185006 / ~190041 consumed the
 *  signer's tokens; nyc1 (84 behind) never appeared in the serve log and
 *  stayed at ~36s/block ExactReplay. Do not regenerate ExactReplay. */
static constexpr int SIGNER_GETMMATTEST_CACHED_CATCHUP_WINDOW{256};
/** Consecutive ignored GETMMATTEST (rate-limited serve or historical
 *  probe on a signer) before the peer is disconnected and banned for
 *  24h. Aggressive P2P is penalized; a silent drop is not enough
 *  because the peer can reconnect and keep filling the accept queue. */
static constexpr int GETMMATTEST_HAMMER_BAN_AFTER{32};

/** Archives serve historical GETMMATTEST. A local signer does not:
 *  only the live tip window. Height above tip (catch-up suffix) is
 *  inside the window. */
[[nodiscard]] inline bool TrustedSignerMayServeGetMmAttest(
    bool has_local_signer,
    int32_t height,
    int32_t tip_height,
    int serve_window = SIGNER_GETMMATTEST_SERVE_WINDOW)
{
    if (!has_local_signer) return true;
    if (height < 0 || tip_height < 0 || serve_window < 0) return false;
    return height + serve_window >= tip_height;
}

/** Cached MMATTEST for an archive / trusted-mirror catch-up peer on our
 *  active chain, even outside the live window, while the hash is still
 *  inside SIGNER_GETMMATTEST_CACHED_CATCHUP_WINDOW of the signer tip.
 *  Live 2026-08-16: nyc1 asked GETMMATTEST for 190689 while the GPU tip
 *  was 190795; the 16-high window returned historical_not_served. Opening
 *  cached serve to every addnode/manual then starved nyc1 (tokens went to
 *  185006 / 190041 historical probes). Do not authorize ExactReplay.
 *
 *  An empty hot/durable cache is not a refuse: see
 *  TrustedSignerMayRegenerateCatchUpGetMmAttest. */
[[nodiscard]] inline bool TrustedSignerMayServeCachedCatchUpGetMmAttest(
    bool has_local_signer,
    bool requester_is_catchup_peer,
    bool on_active_chain,
    int32_t height,
    int32_t tip_height,
    int serve_window = SIGNER_GETMMATTEST_SERVE_WINDOW,
    int cached_catchup_window = SIGNER_GETMMATTEST_CACHED_CATCHUP_WINDOW)
{
    if (TrustedSignerMayServeGetMmAttest(
            has_local_signer, height, tip_height, serve_window)) {
        return true;
    }
    if (!has_local_signer || !requester_is_catchup_peer || !on_active_chain) {
        return false;
    }
    if (height < 0 || tip_height < 0 || cached_catchup_window < 0) {
        return false;
    }
    return height + cached_catchup_window >= tip_height;
}

/** Empty-cache regeneration after CachedCatchUp admitted the request.
 *  SignAuthoritative only — never ExactReplay (that saturates the signer
 *  and the uplink). Live 2026-08-17: GPU restart left 191593 unsigned;
 *  !live_window refused regen; nyc1 had the body and stayed at 191592.
 *  The 256-high window and archive/mirror bit stay fail-closed so IBD
 *  185006 / 190041 probes cannot drain tokens. */
[[nodiscard]] inline bool TrustedSignerMayRegenerateCatchUpGetMmAttest(
    bool has_local_signer,
    bool requester_is_catchup_peer,
    bool on_active_chain,
    int32_t height,
    int32_t tip_height,
    int serve_window = SIGNER_GETMMATTEST_SERVE_WINDOW,
    int cached_catchup_window = SIGNER_GETMMATTEST_CACHED_CATCHUP_WINDOW)
{
    // Live window already regenerates via the ExactReplay-verified path.
    if (TrustedSignerMayServeGetMmAttest(
            has_local_signer, height, tip_height, serve_window)) {
        return false;
    }
    return TrustedSignerMayServeCachedCatchUpGetMmAttest(
        has_local_signer, requester_is_catchup_peer, on_active_chain,
        height, tip_height, serve_window, cached_catchup_window);
}

/** While a trusted mirror is behind the GPU-signed frontier, historical
 *  GETMMATTEST serve is not this node's job: msghand must process BLOCK /
 *  getdata. Same live window as a signer. Caught-up archives still serve
 *  history. */
[[nodiscard]] inline bool TrustedArchiveMayServeGetMmAttest(
    bool catching_up_behind_frontier,
    int32_t height,
    int32_t tip_height,
    int serve_window = SIGNER_GETMMATTEST_SERVE_WINDOW)
{
    if (!catching_up_behind_frontier) return true;
    return TrustedSignerMayServeGetMmAttest(
        /*has_local_signer=*/true, height, tip_height, serve_window);
}

/** True once ignored GETMMATTEST / inbound MMATTEST floods reach the
 *  ban threshold. Callers must Ban (not only Discourage): discouraged
 *  peers may still reconnect while inbound slots remain. */
[[nodiscard]] inline bool AggressiveGetMmAttestShouldBan(
    int consecutive_ignored,
    int threshold = GETMMATTEST_HAMMER_BAN_AFTER)
{
    return consecutive_ignored >= threshold;
}

/** LCA(tip, candidate) depth in (0, TRUSTED_MIRROR_SHORT_REORG_DEPTH].
 *  Depth 0 is the tip itself; depth 7+ is the EMERGENCY park window and the
 *  competing miner fork (live: ~200 headers at 1879xx vs a 187773 sibling). */
[[nodiscard]] inline bool TrustedMirrorIsShortTipReorg(int lca_depth)
{
    return lca_depth > 0 && lca_depth <= TRUSTED_MIRROR_SHORT_REORG_DEPTH;
}

/** FindUniqueCompetingAttestedIndex adoption gate.
 *
 *  Catch-up suffix of the active tip (LCA depth 0, idx above tip) is
 *  always eligible. Competing forks are short-reorg only (depth 1–6)
 *  unless `idx` sits on the current signed-frontier chain. Once a concrete
 *  highest signed-frontier hash is known, an older off-frontier quorum
 *  remains validity provenance but is no longer a fork-choice signal.
 *  Re-adopting one made duplicate canonical block delivery oscillate back
 *  to a stale height-33 twin while the frontier advanced through 35–48
 *  during trusted-mirror convergence.
 *
 *  Fossils off the current frontier also stay bounded: the previous
 *  unbounded `tip_has_quorum == false` path let a stale MMATTEST hijack
 *  FMWC into a 510-block rollback (PR 105 field report 2026-08-15). The
 *  signed-frontier exception is the live archive recovery path: trusted
 *  mirrors crawled 13–180 unattested HAVE_DATA blocks while the attested
 *  suffix was HEADER_ONLY. That exception remains subject to an explicit
 *  parked-branch boundary; only an operator may release a deep rewrite once
 *  local PARK policy has recorded it. */
[[nodiscard]] inline bool TrustedMirrorMayAdoptCompetingAttestedIndex(
    bool attested_suffix_of_active_tip,
    int lca_depth,
    bool on_signed_frontier_chain,
    bool signed_frontier_hash_known,
    bool on_parked_reorg_branch = false)
{
    // PARK is an explicit operator finality boundary. A current signer quorum
    // authenticates ExactReplay validity, but must not silently unpark a deep
    // rewrite and turn validity provenance into an override of local policy.
    if (on_parked_reorg_branch) return false;
    if (on_signed_frontier_chain) return true;
    if (signed_frontier_hash_known) return false;
    return attested_suffix_of_active_tip || TrustedMirrorIsShortTipReorg(lca_depth);
}

/** Quorum tip vs signed frontier that has pulled ahead on a competing fork.
 *
 *  Same-height dual-quorum twins must not flip-flop (live 190354
 *  CONSENSUS reversal). When the signed frontier is strictly ahead,
 *  FindUnique must nominate that frontier — not the same-height
 *  fork-child. Returning the fork-child forced a dual-quorum switch
 *  that both CONSENSUS and TRUSTED refuse, pinning a self-signed losing
 *  twin (live 2026-08-17 miner: consensus at 191323 / 191397, then
 *  `-matmulvalidation=trusted` still stuck, blocks_behind=7, until the
 *  local attestation store was moved aside).
 */
[[nodiscard]] inline bool ConsensusSignerMayAbandonQuorumTipForSignedFrontier(
    bool unique_on_signed_frontier_chain,
    int32_t unique_height,
    int32_t tip_height)
{
    return unique_on_signed_frontier_chain && unique_height > tip_height;
}

/** Independent consensus ExactReplay GPU (no local signer, not trusted
 *  mirror). Competing unattested twins must not take the device: live
 *  2026-08-17 miner mode 1 filled the scheduler (workspace=5164972400B)
 *  and froze CandidateMining. A later consensus miner on e6249edd still
 *  lost the near-tip lottery because `pprev==tip` admitted every
 *  unattested sibling (~50 bodies/height) and ExactReplay'd them ahead
 *  of local submitblock.
 *
 *  Local submitblock uses CandidateMining, not this P2P admission path.
 *  Independent consensus follows attestation: unattested tip-children
 *  stay off-device (GETMMATTEST first). Hashes covered by the signed
 *  frontier / quorum still replay so ConnectTip can take the lottery
 *  winner. Already-canonical near-tip holes stay on-device for IBD. */
[[nodiscard]] inline bool IndependentConsensusMaySpendExactReplayGpu(
    bool pprev_is_tip,
    bool on_or_extends_active_tip,
    int32_t index_height,
    int32_t tip_height,
    int32_t near_tip_depth,
    bool covered_by_attestation)
{
    if (covered_by_attestation) return true;
    // Unattested pprev==tip is the twin storm. Do not ExactReplay a
    // competing sibling just because it extends the tip.
    if (pprev_is_tip) return false;
    if (on_or_extends_active_tip) {
        return index_height >= tip_height - near_tip_depth &&
               index_height <= tip_height;
    }
    return false;
}

/** Equal-work lost twin (live 2026-08-20 consensus node): unattested tip
 *  at H, attested sibling at H, signed frontier HEADER_ONLY at H+N.
 *  The winner's pprev is the LCA, not the current tip, so the local-signer
 *  ExactReplay gate (pprev==tip) HEADER_ONLY-skipped it forever. Spend GPU
 *  only for the immediate attested fork-child of a short reorg (depth 1–6)
 *  while the tip itself has no quorum. Dual-attested same-height twins,
 *  parked branches, fossils, and already-canonical ancestors stay off. */
[[nodiscard]] inline bool ConsensusMaySpendExactReplayGpuForShortReorgForkChild(
    bool configured,
    bool tip_has_quorum,
    bool index_covered_by_attestation,
    bool index_is_tip,
    int lca_depth,
    bool is_immediate_fork_child,
    bool index_on_active_chain,
    bool has_competing_quorum,
    bool on_parked)
{
    if (!configured || index_is_tip || on_parked || index_on_active_chain) {
        return false;
    }
    if (tip_has_quorum || has_competing_quorum) return false;
    if (!index_covered_by_attestation || !is_immediate_fork_child) return false;
    return TrustedMirrorIsShortTipReorg(lca_depth);
}

/** While the signed frontier is off the active chain, budget-deferred
 *  retry may only re-admit the attested fork-child / frontier path.
 *  Historical losing twins (live 195579/195599/195601) occupied admission
 *  every 20s–2min with GPU at 0% and inflight=0. */
[[nodiscard]] inline bool ShouldRetryBudgetDeferredWhileFrontierOffChain(
    bool frontier_off_active_chain,
    bool hash_is_short_reorg_attested_fork_child,
    bool hash_on_signed_frontier_chain,
    bool hash_is_followed_tip_child)
{
    if (!frontier_off_active_chain) return true;
    return hash_is_short_reorg_attested_fork_child ||
           hash_on_signed_frontier_chain ||
           hash_is_followed_tip_child;
}

/** Skip FindUniqueCompetingAttestedIndex's HEADER_ONLY-hole pprev walk.
 *  If `idx` is already on the active chain, LastCommonAncestor(tip, idx)
 *  is `idx`. Walking `idx->pprev` until that LCA never hits `idx` and
 *  runs to genesis (live nyc1: 512 frontier hints × ~190k = ~19s
 *  FindMostWorkChain, GPU VERSION starved, in_flight=0). */
[[nodiscard]] inline bool TrustedMirrorAttestedHintIsActiveAncestor(
    bool on_active_chain,
    bool lca_is_index)
{
    return on_active_chain || lca_is_index;
}

/** True when `index` is a strict descendant of the active tip (catch-up
 *  suffix). Same-height twins are not this: GetAncestor(tip) is the twin
 *  itself. The 1879xx competing fork is not this either. Immediate
 *  tip-children (`index_height == tip_height + 1`) also match; those
 *  competing siblings stay HEADER_ONLY except the claimed/followed child. */
[[nodiscard]] inline bool TrustedMirrorIndexExtendsActiveTip(
    bool has_tip,
    bool has_index,
    int32_t index_height,
    int32_t tip_height,
    bool index_ancestor_at_tip_is_tip)
{
    return has_tip && has_index && index_height > tip_height &&
           index_ancestor_at_tip_is_tip;
}

/** Catch-up suffix beyond the immediate tip-child (grandchildren+).
 *  Trusted mirrors must persist / re-getdata these; HEADER_ONLY-skipping
 *  them wedges FindMostWorkChain because the tip cannot move. Immediate
 *  competing siblings are not this. */
[[nodiscard]] inline bool TrustedMirrorIndexIsCatchUpSuffix(
    bool has_tip,
    bool has_index,
    int32_t index_height,
    int32_t tip_height,
    bool index_ancestor_at_tip_is_tip)
{
    return TrustedMirrorIndexExtendsActiveTip(
               has_tip, has_index, index_height, tip_height,
               index_ancestor_at_tip_is_tip) &&
           index_height > tip_height + 1;
}

/** FindMostWorkChain / candidate-set gate for any node that tracks a
 *  configured attestation quorum (trusted mirror, local signer, or
 *  consensus + -matmultrustedpubkey).
 *
 *  Immediate unattested tip-children stay selectable (HAVE_DATA
 *  chicken-egg). Unattested grandchildren / pre-built towers are not:
 *  once the signer connected the wrong twin, the tower became
 *  "tip-extending" and was attested as a stack (live 2026-08-15 190354
 *  and the 67-block 190333–190400 fork). Selection is not the connect
 *  gate: TrustedMirrorMustDeferUnattestedConnect still refuses ConnectTip
 *  of an unattested Profile-1 block on a trusted mirror. A short attested
 *  tip-race (LCA depth 1–6 with quorum) may replace an *unattested* tip so
 *  a lost same-height sibling can converge.
 *
 *  Never reorg away a tip that already has quorum via this gate. Live
 *  2026-08-13: the signer followed a heavier 4-block competing fork at
 *  187795, signed it, and every mirror treated that as an attested short
 *  race. Competing then extended as "tip-extending" to 18781x.
 *
 *  Never select an unattested candidate that would disconnect a quorum
 *  ancestor, or that shares a height with a different already-attested
 *  hash (dual-attest mint). Dual-attested same-height siblings (legacy:
 *  both 189489 hashes signed) are recovered by
 *  FindUniqueCompetingAttestedIndex following the signed frontier, not
 *  by this gate.
 *
 *  A node already sitting on an unattested tip (equal-work lost sibling
 *  or heavier unattested fork) is recovered by
 *  FindUniqueCompetingAttestedIndex, not by this gate. A CONSENSUS local
 *  signer whose tip already has quorum (self-mined losing twin) is also
 *  recovered there when the signed frontier has pulled ahead on the
 *  competing fork — not by this gate, and not by operator invalidateblock.
 *
 *  When the signed frontier is on a competing fork (the active tip does
 *  not lead to any stored frontier hash), do not keep selecting unattested
 *  tip-children: that is the archive crawl that walked 190333→190346
 *  while attested bodies sat HEADER_ONLY. FindUnique + getdata of the
 *  signed-frontier path recover; this gate must stop the unattested walk.
 *
 *  Being *behind* the frontier on the same chain (tip height < frontier
 *  height, on_active_chain=false as a diagnostic) is catch-up, not a
 *  competing fork. Live 2026-08-16 miners: that diagnostic was used as
 *  this gate, TryAdd refused the HEADER_ONLY tip-child, and FMWC spun on
 *  the 274-block 190333 headers-only tower. */
[[nodiscard]] inline bool TrustedMirrorMaySelectMostWorkCandidate(
    bool extends_active_tip_chain,
    bool short_tip_reorg,
    bool has_quorum,
    bool active_tip_has_quorum = false,
    bool immediate_tip_child = true,
    bool would_abandon_attested = false,
    bool competing_attested_height = false,
    bool signed_frontier_on_competing_fork = false)
{
    if (signed_frontier_on_competing_fork && !has_quorum) return false;
    if (would_abandon_attested && !has_quorum) return false;
    if (competing_attested_height && !has_quorum) return false;
    if (extends_active_tip_chain) {
        return has_quorum || immediate_tip_child;
    }
    if (active_tip_has_quorum) return false;
    return short_tip_reorg && has_quorum;
}

/** ConnectTip / ActivateBestChainStep gate for a trusted Profile-1 node.
 *  Tip-extending HAVE_DATA stays selectable so a consensus signer can
 *  getdata an unattested tip-child (chicken-egg with archives). Quorum
 *  still gates activation of hashes the GPU has not attested.
 *
 *  Lift ConnectTip / ExactReplay only when a GPU attestation covers
 *  this hash: in-memory quorum, durable verified signatures, or
 *  signed-frontier ancestry. Catch-up height is not attestation.
 *  Blocks *above* the frontier stay deferred. */
[[nodiscard]] inline bool TrustedMirrorMustDeferUnattestedConnect(
    bool trusted_mirror_profile1,
    bool has_quorum,
    bool covered_by_signed_frontier = false)
{
    return trusted_mirror_profile1 && !has_quorum &&
           !covered_by_signed_frontier;
}

/** FindMostWorkChain may return this candidate without scanning a heavier
 *  unattested HEADER_ONLY / claimed-work tower. Covered HAVE_DATA on a
 *  trusted-mirror tip-extension is the millisecond ConnectTip path; walking
 *  headers=191013 vs an attested frontier was the live 25–60s stall after
 *  `matmul accept-path path=frontier ms=0.0`. */
[[nodiscard]] inline bool TrustedMirrorPreferCoveredConnectCandidate(
    bool trusted_mirror,
    bool extends_active_tip,
    bool have_data_connectable,
    bool covered_or_quorum)
{
    return trusted_mirror && extends_active_tip && have_data_connectable &&
           covered_or_quorum;
}

/** Trusted-mirror FindMostWorkChain is attested-GPU selection, not
 *  Bitcoin most-work among miner header towers. When nothing attested
 *  (or the next GPU tip-child body) is connectable, yield immediately
 *  so SendMessages can GETDATA. Other attested attestor forks stay in
 *  the candidate set for the next ABC step — cooperative, not a second
 *  cs_main walker. */
[[nodiscard]] inline bool TrustedMirrorMostWorkYieldsUnattestedTower(
    bool trusted_mirror,
    bool have_attested_connectable,
    bool have_immediate_have_data_tip_child)
{
    return trusted_mirror && !have_attested_connectable &&
           !have_immediate_have_data_tip_child;
}

/** Evict a competing claimed-work tower from FindMostWorkChain without
 *  walking its HEADER_ONLY parents (AddUnlinkedBlock / missing-data).
 *  Immediate tip-children and the unique attested-abandon target stay. */
[[nodiscard]] inline bool TrustedMirrorSkipUnattestedClaimedWorkTower(
    bool trusted_mirror,
    bool leads_to_signed_frontier,
    bool immediate_tip_child,
    bool unique_abandon_target)
{
    if (!trusted_mirror) return false;
    if (unique_abandon_target) return false;
    if (immediate_tip_child) return false;
    return !leads_to_signed_frontier;
}

/** CONSENSUS signer / configured node: never ConnectTip an unattested
 *  hash at a height that already has quorum on a different hash. */
[[nodiscard]] inline bool MustDeferConflictingAttestedHeight(
    bool configured,
    bool candidate_has_quorum,
    bool competing_attested_height,
    bool covered_by_signed_frontier = false)
{
    // A later GPU-signed frontier covers this ancestor: a stale competing
    // quorum at the same height must not block the attested path. The
    // competing hash itself is not covered (GetAncestor fails).
    if (covered_by_signed_frontier) return false;
    return configured && !candidate_has_quorum && competing_attested_height;
}

/** True when an alternate index may defer an unattested most-work candidate.
 *
 *  Qualifier 3ed2619c (PR 105): the active tip is always in
 *  setBlockIndexCandidates and is usually attested. Counting it — or any
 *  stale/non-distinct candidate-set entry — as an "attested sibling"
 *  permanently deferred the sole linear tip-child (behind=1, 83 repeats).
 *  Deferral is valid only for a distinct same-height child of the current
 *  tip — or a same-height attested twin of the tip (live 2026-08-15) —
 *  that still has quorum and is not FAILED. Headers-only + quorum is
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
 *  on the authority peer's best-known), or a followed-chain HAVE_DATA /
 *  retained GPU body still waiting for MMATTEST. Competing headers at
 *  1879xx are neither. Parked deep-reorg branches never prefer.
 *
 *  During signed-frontier catch-up the moving frontier hash and a recent
 *  active ancestor are not preferred. Live sfo3 2026-08-20: catch_up=1,
 *  needed_height=194728, GETMMATTEST send hammered mid-suffix 194999
 *  (stale frontier) and the current frontier (no_such_block) so tip+1
 *  never got a slot. */
[[nodiscard]] inline bool TrustedMirrorPreferGetMmAttest(
    bool active_tip_child,
    bool short_tip_reorg_missing_root,
    bool on_parked_reorg_branch = false,
    bool recent_active_ancestor = false,
    bool followed_body_awaiting_attestation = false,
    bool is_signed_frontier_hash = false,
    bool signed_frontier_catch_up = false)
{
    if (on_parked_reorg_branch) return false;
    const bool hole{active_tip_child || short_tip_reorg_missing_root ||
                    followed_body_awaiting_attestation};
    if (signed_frontier_catch_up) return hole;
    return hole || recent_active_ancestor || is_signed_frontier_hash;
}

/** Catch-up must not allocate a GETMMATTEST slot for a non-hole hash.
 *  Non-preferred requests still occupied 16 mid-suffix slots on sfo3
 *  (outstanding_slots=16/1024, rejected_unattestable climbing) while
 *  194728 sat HEADER_ONLY with local quorum and in_flight=0. */
[[nodiscard]] inline bool TrustedMirrorCatchUpShouldRequestGetMmAttest(
    bool signed_frontier_catch_up,
    bool preferred)
{
    if (!signed_frontier_catch_up) return true;
    return preferred;
}

/** GETMMATTEST destinations. NODE_MATMUL_ATTESTATION_ARCHIVE means the
 *  peer answers GETMMATTEST (signer that still serves, or a trusted
 *  mirror cache-and-forwarding accepted signatures). Trusted mirrors
 *  cannot SignAuthoritative. Consensus nodes that still serve are a
 *  fallback; a signer with -matmulattestationserve=0 keeps CONSENSUS
 *  but replies not_serving without taking cs_main. Ordinary miners
 *  with no CONSENSUS / ARCHIVE / MIRROR bit still skip. Direct signer
 *  addnode must not be required. */
[[nodiscard]] inline bool PreferGetMmAttestPeer(
    bool has_attestation_archive_bit,
    bool recent_valid_mmattest,
    bool trusted_mirror = false,
    bool consensus_node = false,
    bool signed_frontier_catch_up = false,
    bool gpu_attestor = false)
{
    if (has_attestation_archive_bit || recent_valid_mmattest ||
        trusted_mirror) {
        return true;
    }
    // Live 2026-08-16: trusted-mirror archives sprayed GETMMATTEST at every
    // NODE_MATMUL_CONSENSUS miner while catching up a HEADER_ONLY suffix.
    // Those peers have no store (0 replies) and must not occupy miss-backoff
    // while an archive / signer is the body+attestation source. The GPU
    // attestor is that source even when its advertised bits are CONSENSUS
    // only (no ARCHIVE) and catch-up would otherwise skip consensus_node.
    if (gpu_attestor) return true;
    if (signed_frontier_catch_up) return false;
    return consensus_node;
}

/** Trusted mirror catching up a followed HEADER_ONLY suffix.
 *
 *  Not assumeutxo / unattested IBD: those keep the wide 16-slot window.
 *  Live 2026-08-16: ahead≥32 AND 15s catch-up timeout filled 16 getdatas
 *  from miners who only had headers — keep this 1-wide and GPU-only.
 *
 *  A known frontier with blocks_behind=0 plus miner HEADER_ONLY children
 *  is not catch-up (live signer: tip==frontier, m_best_header +13).
 *  After restart the in-memory store is empty (frontier_available=false)
 *  while a GPU suffix already sits HEADER_ONLY in the index — that IS
 *  catch-up (live archives 2026-08-17: headers=191690, sent_getdata=0). */
[[nodiscard]] inline bool IsSignedFrontierCatchUp(
    bool trusted_mirror,
    bool configured,
    int32_t blocks_behind,
    int followed_ahead,
    int stall_headers_ahead = 2,
    bool frontier_available = true)
{
    if (!trusted_mirror || !configured) return false;
    if (followed_ahead < stall_headers_ahead) return false;
    if (frontier_available) {
        return blocks_behind >= stall_headers_ahead;
    }
    return true;
}

/** Ancestor of (or equal to) a GPU-signed frontier hash.
 *  Descendants *above* the frontier are not covered — those still need
 *  their own quorum. Distinct from IndexIsOnSignedFrontierChain, which
 *  also returns true for unattested tip-children of the frontier. */
[[nodiscard]] inline bool TrustedMirrorFrontierCoversBlock(
    bool frontier_available,
    int32_t block_height,
    int32_t frontier_height,
    bool frontier_descends_from_block)
{
    return frontier_available && block_height >= 0 &&
           frontier_height >= 0 && block_height <= frontier_height &&
           frontier_descends_from_block;
}

/** How far catch-up may treat the followed header chain as "ahead".
 *
 *  Raw tip-extending m_best_header height is the wrong number once a
 *  signed frontier exists: collapsed difficulty lets miners stack
 *  unattested HEADER_ONLY children on the attested tip (live signer
 *  2026-08-16: tip=190617 frontier=190617, m_best_header=190630). That
 *  kept IsCatchUpBlockFetch / MaybeRecoverStalledBlockFetch in a
 *  permanent stall (in_flight=0, no_missing_body) and pegged b-msghand
 *  so the signer could neither mine nor serve bodies.
 *
 *  Cap at the signed frontier. A competing fork (tip does not lead to
 *  the frontier) is not catch-up — FindUnique handles rejoin. */
[[nodiscard]] inline int CappedFollowedCatchUpAhead(
    bool configured,
    bool frontier_available,
    int tip_height,
    int followed_header_height,
    int signed_frontier_height,
    bool tip_leads_to_frontier)
{
    const int raw{std::max(0, followed_header_height - tip_height)};
    if (!configured || !frontier_available) return raw;
    if (!tip_leads_to_frontier) return 0;
    return std::max(0, std::min(followed_header_height, signed_frontier_height) -
                           tip_height);
}

/** Root-first 1-wide getdata while catching up. Live nyc1 2026-08-16:
 *  treating signed-frontier catch-up as *wide* walked HeadersDirectFetch
 *  from last_header and filled 16 newest hashes (190841/190842) while
 *  tip+1 (190777) sat HEADER_ONLY; those slots then timed out at ~100s.
 *  GPU attestation already covers the ancestor path, so the body at
 *  tip+1 is O(1) accept — serial root-first is body-download speed,
 *  not ExactReplay. Unattested near-tip holes stay 1-wide. IBD is wide. */
[[nodiscard]] inline bool IsNarrowCatchUpWindowForPolicy(
    bool ibd,
    int ahead,
    bool signed_frontier_catch_up,
    int stall_headers_ahead = 2,
    int narrow_max_ahead = 32)
{
    if (ibd) return false;
    if (ahead < stall_headers_ahead) return false;
    if (signed_frontier_catch_up) return true;
    return ahead < narrow_max_ahead;
}

/** Who may take getdata during signed-frontier catch-up.
 *  Preferred sources: (1) the GPU connection (manual/noban, inbound FROM
 *  the signer or outbound -connect TO it), (2) OUR outbound connections
 *  to NODE_MATMUL_ATTESTATION_ARCHIVE / NODE_MATMUL_TRUSTED_MIRROR.
 *  Inbound miners and inbound archive-bit peers are not GETDATA sources
 *  (live nyc1: seeding BestKnown onto every handshake inbound and asking
 *  them for tip+1 is the wrong direction). A recent valid MMATTEST does
 *  *not* qualify a miner. When signed_frontier_catch_up is false this
 *  is not a gate. */
[[nodiscard]] inline bool PreferSignedFrontierCatchUpBlockPeer(
    bool signed_frontier_catch_up,
    bool has_archive_bit,
    bool trusted_mirror_peer,
    bool node_network,
    bool recent_valid_mmattest,
    bool manual_or_noban,
    bool outbound = true)
{
    (void)recent_valid_mmattest;
    (void)node_network;
    if (!signed_frontier_catch_up) return true;
    if (manual_or_noban) return true;
    if (outbound && (has_archive_bit || trusted_mirror_peer)) {
        return true;
    }
    return false;
}

/** VERSION finished: starting_height is set from the VERSION message
 *  (-1 until then). Service bits / seeded BestKnown must not stand in
 *  for a hung -connect (bytesrecv=0). */
[[nodiscard]] inline bool SignedFrontierVersionHandshakeComplete(
    int starting_height)
{
    return starting_height >= 0;
}

/** Preferred source actually knows the catch-up suffix (headers that
 *  extend the active tip) *and* has finished VERSION. Handshake-only
 *  addnode / seeded BestKnown with empty services must not count: that
 *  skipped archives while the GPU -connect sat at bytesrecv=0 (live
 *  nyc1 2026-08-16 after root-first: in_flight=0, sent_getdata=0). */
[[nodiscard]] inline bool SignedFrontierPeerHadCatchUpBodiesAtConnect(
    int starting_height,
    int tip_height)
{
    // No VERSION: cannot serve. A peer whose VERSION height is at or behind
    // our *active* tip does not have tip+1 at handshake (live nyc1
    // 2026-08-16: sibling archives were preferred-capable from headers
    // alone, GETDATA timed out, miners were skipped).
    // Compare to the connected tip, never to m_best_header: miner
    // HEADER_ONLY children stacked on the attested tip made
    // starting_height > followed_header fail while the peer still had
    // every body from tip+1 through the signed frontier (live GPU-archive
    // catch-up 2026-08-19: VERSION 194111 vs m_best_header 194116, tip
    // 189534, inflight=0).
    return starting_height > tip_height;
}

/** Root-first catch-up GETDATA asks for active-tip+1, not m_best_header.
 *  VERSION is a handshake snapshot (lower bound on bodies the peer *had*),
 *  not a live connected height. After this node climbs past that snapshot,
 *  a still-connected archive whose BestKnown extends our tip can still
 *  serve historical tip+1 (live 2026-08-19: VERSION 194111, tip 194121,
 *  BestKnown 194160, stall recovery logged every 60s with inflight=0).
 *  Behind-sibling VERSION < tip with no extending BestKnown stays refused
 *  (live nyc1 2026-08-17: 190767 vs 190816). */
[[nodiscard]] inline bool SignedFrontierPeerMayServeCatchUpTipPlusOne(
    int starting_height,
    int active_tip_height,
    int best_known_height = std::numeric_limits<int>::min(),
    bool best_known_extends_tip = false)
{
    if (starting_height < 0) return false;
    if (SignedFrontierPeerHadCatchUpBodiesAtConnect(starting_height,
                                                    active_tip_height)) {
        return true;
    }
    return best_known_extends_tip && best_known_height > active_tip_height;
}

/** A valid Accepted/Duplicate MMATTEST for a known non-failed Profile-1
 *  header proves the peer has that hash. BestKnown used to move only on
 *  INV/HEADERS/CMPCTBLOCK, so a 1-of-2 attestor that only relayed
 *  attestations and bodies stayed pinned at the last header announcement.
 *  That made FindNextBlocks skip the peer, CHAIN_SYNC_TIMEOUT treat it as
 *  an old chain, and catch-up GETDATA/GETMMATTEST use a stale pointer.
 *  Rejected / unknown / failed headers must not advance it (competing
 *  HEADER_ONLY towers stay untrusted). */
[[nodiscard]] inline bool ShouldAdvanceBestKnownFromMmAttest(
    bool known_profile1,
    bool header_failed,
    matmul::trusted::AddResult result)
{
    if (!known_profile1 || header_failed) return false;
    return result == matmul::trusted::AddResult::Accepted ||
           result == matmul::trusted::AddResult::Duplicate;
}

/** A connected, non-failed body also proves availability. HEADER_ONLY,
 *  deferred, mutated, or failed deliveries must not move BestKnown. */
[[nodiscard]] inline bool ShouldAdvanceBestKnownFromPeerBody(
    bool have_index,
    bool header_failed,
    bool have_data)
{
    return have_index && !header_failed && have_data;
}

/**
 * Attestor↔attestor drift yield (1-of-2 / M-of-N GPU signers).
 *
 * Local signers are not trusted mirrors, so IsSignedFrontierCatchUp never
 * arms on them. After two GPUs sit on the same tip they also stop
 * announcing headers; even with BestKnown advancing from MMATTEST/body,
 * the loser can sit on root_retained_body with in_flight=0 while GETMMATTEST
 * tokens go to competing HEADER_ONLY twins (live 2026-08-20: tip 194828,
 * canonical 194829 retained, peer BestKnown 194851, rejected_unattestable
 * 239). Once the gap reaches the operator park depth the longer attested
 * / BestKnown side wins. The loser immediately re-admits the retained
 * canonical body and GETMMATTEST/GETDATA that suffix from the winning GPU
 * only. Public / miner peers and failed / off-path hashes stay refused.
 */
static constexpr int32_t ATTESTOR_DRIFT_YIELD_DEPTH{6};

/** Resolve the yield threshold. Disabled / unset park uses the EMERGENCY
 *  default of 6 so a 1-block race does not force a yield. */
[[nodiscard]] inline int32_t AttestorDriftYieldDepth(uint32_t configured_park)
{
    if (configured_park == 0 ||
        configured_park == std::numeric_limits<uint32_t>::max()) {
        return ATTESTOR_DRIFT_YIELD_DEPTH;
    }
    if (configured_park > static_cast<uint32_t>(
            std::numeric_limits<int32_t>::max())) {
        return ATTESTOR_DRIFT_YIELD_DEPTH;
    }
    return static_cast<int32_t>(configured_park);
}

/** This GPU peer is at least `park_depth` ahead of our tip. */
[[nodiscard]] inline bool AttestorShouldYieldToPeerAttestedChain(
    bool local_signer,
    bool peer_is_gpu_attestor,
    int32_t local_tip_height,
    int32_t peer_known_height,
    int32_t park_depth)
{
    if (!local_signer || !peer_is_gpu_attestor) return false;
    if (park_depth <= 0 || local_tip_height < 0 || peer_known_height < 0) {
        return false;
    }
    return peer_known_height >= local_tip_height + park_depth;
}

/** Signed frontier (any stored quorum) has pulled ahead by park depth. */
[[nodiscard]] inline bool AttestorShouldYieldToSignedFrontier(
    bool local_signer,
    int32_t blocks_behind,
    int32_t park_depth)
{
    if (!local_signer || park_depth <= 0 || blocks_behind < 0) return false;
    return blocks_behind >= park_depth;
}

/** Canonical hole on the winner / signed-frontier chain. Competing
 *  same-height HEADER_ONLY twins are not this. */
[[nodiscard]] inline bool AttestorYieldHashIsCatchUpTarget(
    bool yielding,
    bool on_winner_or_signed_frontier_chain,
    bool header_failed)
{
    return yielding && on_winner_or_signed_frontier_chain && !header_failed;
}

/** GETMMATTEST destinations while yielding: GPU attestors only. */
[[nodiscard]] inline bool AttestorYieldPreferGetMmAttestPeer(
    bool yielding,
    bool gpu_attestor)
{
    if (!yielding) return true;
    return gpu_attestor;
}

/** While yielding, request only the winner's attested suffix. */
[[nodiscard]] inline bool AttestorYieldShouldRequestGetMmAttest(
    bool yielding,
    bool on_winner_or_signed_frontier_chain)
{
    if (!yielding) return true;
    return on_winner_or_signed_frontier_chain;
}

/** Re-admit the retained canonical body now (retry delay 0) instead of
 *  sitting in root_retained_body while the winner walks away. */
[[nodiscard]] inline bool AttestorYieldMustReadmitRetainedBody(
    bool yielding,
    bool have_retained_body,
    bool hash_is_catch_up_target)
{
    return yielding && have_retained_body && hash_is_catch_up_target;
}

[[nodiscard]] inline bool SignedFrontierBodySourceCanServeCatchUp(
    bool preferred,
    bool has_best_known,
    int best_known_height,
    int tip_height,
    bool best_known_extends_tip,
    bool version_handshake_complete = true,
    int starting_height = std::numeric_limits<int>::max())
{
    if (!version_handshake_complete) return false;
    if (!SignedFrontierPeerMayServeCatchUpTipPlusOne(
            starting_height, tip_height, best_known_height,
            best_known_extends_tip)) {
        return false;
    }
    return preferred && has_best_known && best_known_height > tip_height &&
           best_known_extends_tip;
}

/** Who may receive a signed-frontier BestKnown seed. GPU (manual/noban)
 *  in either direction after VERSION, or OUR outbound archive/mirror
 *  that advertised ahead of tip. Never inbound miners / inbound
 *  archive-bit peers (that "seed everyone inbound" path asked them for
 *  tip+1; they timed out and flapped in_flight). */
[[nodiscard]] inline bool SignedFrontierMaySeedBestKnownFromFrontier(
    bool gpu_manual_or_noban,
    bool outbound,
    bool archive_or_mirror,
    int starting_height,
    int tip_height)
{
    if (gpu_manual_or_noban) return true;
    if (!outbound || !archive_or_mirror) return false;
    return SignedFrontierPeerHadCatchUpBodiesAtConnect(starting_height,
                                                       tip_height);
}

/** GPU -connect VERSION does not set pindexBestKnownBlock. getheaders from
 *  m_best_header asks for *new* headers; the HEADER_ONLY catch-up suffix is
 *  already on disk. Seed BestKnown from the signed frontier only on GPU
 *  or outbound attested archives (see SignedFrontierMaySeedBestKnownFromFrontier).
 *  A competing BestKnown (headers=191013 vs frontier) must be overwritten. */
[[nodiscard]] inline bool SeedTrustedMirrorGpuBestKnownFromFrontier(
    bool signed_frontier_catch_up,
    bool best_known_usable_for_catch_up,
    bool seed_extends_tip,
    int seed_height,
    int tip_height,
    bool version_handshake_complete = true,
    bool may_seed_this_peer = true)
{
    if (!version_handshake_complete) return false;
    if (!may_seed_this_peer) return false;
    if (best_known_usable_for_catch_up) return false;
    return signed_frontier_catch_up && seed_extends_tip &&
           seed_height > tip_height;
}

/** Issue catch-up GETDATA only to handshake-complete GPU, or to our
 *  outbound archive/mirror. Hung -connect (no VERSION) must not occupy
 *  a slot or block those outbounds. `tip_height` is the *active* tip:
 *  root-first asks for tip+1, so miner HEADER_ONLY children on
 *  m_best_header must not raise the VERSION bar. */
[[nodiscard]] inline bool SignedFrontierMayRequestCatchUpGetData(
    bool signed_frontier_catch_up,
    bool gpu_manual_or_noban,
    bool outbound,
    bool archive_or_mirror,
    bool version_handshake_complete,
    int starting_height = std::numeric_limits<int>::max(),
    int tip_height = std::numeric_limits<int>::min(),
    int best_known_height = std::numeric_limits<int>::min(),
    bool best_known_extends_tip = false)
{
    if (!signed_frontier_catch_up) return true;
    if (!version_handshake_complete) return false;
    // Manual/noban includes sibling archive -connect, not only the GPU.
    // Live nyc1 2026-08-17: GETDATA for tip+1 went to a behind sibling
    // (VERSION height 190767 vs tip 190816) and occupied the 1-wide slot.
    if (!gpu_manual_or_noban && (!outbound || !archive_or_mirror)) {
        return false;
    }
    return SignedFrontierPeerMayServeCatchUpTipPlusOne(
        starting_height, tip_height, best_known_height,
        best_known_extends_tip);
}

/** Skip miners / inbound archives during signed-frontier catch-up.
 *  Do not wait for a capable preferred peer: a hung GPU -connect must
 *  not fall through to inbound miners. Preferred GPU / outbound
 *  archives are never skipped. `any_capable` is retained so call sites
 *  stay explicit; it is not a gate. */
[[nodiscard]] inline bool SkipNonPreferredSignedFrontierBodyPeer(
    bool signed_frontier_catch_up,
    bool this_peer_preferred,
    bool any_capable_preferred_peer_connected)
{
    (void)any_capable_preferred_peer_connected;
    return signed_frontier_catch_up && !this_peer_preferred;
}

/** Operator-configured GPU attestor: addnode/connect= / noban, or a peer
 *  that already delivered a valid configured-key MMATTEST (M-of-N). The
 *  self-asserted ARCHIVE bit alone is not GPU authority. */
[[nodiscard]] inline bool TrustedMirrorPeerIsGpuAuthority(
    bool manual_or_noban,
    bool recent_valid_configured_mmattest)
{
    return manual_or_noban || recent_valid_configured_mmattest;
}

/** Handshake finished enough to treat the GPU addnode as live. A TCP
 *  connect with empty VERSION (live manual peer, no services) is not. */
[[nodiscard]] inline bool TrustedMirrorGpuAuthorityHandshakeComplete(
    bool is_gpu_authority,
    bool version_handshake_complete)
{
    return is_gpu_authority && version_handshake_complete;
}

/** PQ v2 hybrid rekey plus FindMostWork CPU can exceed the default
 *  60s -peertimeout before VERSION/VERACK (live nyc1 2026-08-16:
 *  "version handshake timeout" after "post-quantum hybrid rekey
 *  complete", then a new TCP id every 10–60s with ver=0 /
 *  bytesrecv=0). Incomplete handshake that has received bytes
 *  (PQ rekey) still gets at least 180s. Incomplete handshake with
 *  zero bytes received is a dead TCP: 15s so a hung -connect can
 *  recycle. Archives are inbound on the signer, so the incomplete
 *  handshake clause is required there; manual_or_noban alone does
 *  not cover them. Fully connected peers keep the configured
 *  timeout. */
[[nodiscard]] inline std::chrono::seconds TrustedMirrorGpuHandshakeTimeout(
    std::chrono::seconds configured_timeout,
    bool manual_or_noban,
    bool handshake_incomplete = false,
    bool never_received = false)
{
    // Dead TCP: VERSION sent, zero bytes back. 180s existed to survive
    // FindMostWorkChain holding cs_main (~19s). That path is ~65ms now;
    // a bytesrecv=0 addnode must recycle so catch-up GETDATA can run.
    if (handshake_incomplete && never_received) {
        constexpr auto kDead{std::chrono::seconds{15}};
        return std::min(configured_timeout, kDead);
    }
    if (!manual_or_noban && !handshake_incomplete) {
        return configured_timeout;
    }
    constexpr auto kMin{std::chrono::seconds{180}};
    return std::max(configured_timeout, kMin);
}

/** Msghand visit order. Incomplete VERSION/V2 must run before 100+
 *  miner inbounds (archive -connect) and before signer BLOCK serve.
 *  Inbound *archives* with live GETDATA are Preferred. Miner GETDATA
 *  must not be: live macpro2 2026-08-16 after the live-GETDATA patch,
 *  miner GETDATA still sat in Preferred, ProcessGetData sent 1 BLOCK
 *  per visit, one msghand lap was ~45s, nyc1 connected 1 body/cycle. */
enum class MsghandPeerClass : uint8_t {
    Handshake = 0,
    Preferred = 1,
    Other = 2,
};

/** Bound miner (Other) ProcessMessages per msghand loop on a local
 *  signer. Live macpro2 2026-08-16: 8 inbounds each deserialized a
 *  competing BLOCK under cs_main (~5s) so one loop still exceeded the
 *  archive GETDATA window. Handshake + archive GETDATA always run. */
static constexpr int SIGNER_MSGHAND_OTHER_PER_LOOP{2};

[[nodiscard]] inline MsghandPeerClass ClassifyMsghandPeer(
    bool handshake_complete,
    bool manual_or_outbound,
    bool pending_block_serve = false)
{
    if (!handshake_complete) return MsghandPeerClass::Handshake;
    if (manual_or_outbound || pending_block_serve) {
        return MsghandPeerClass::Preferred;
    }
    return MsghandPeerClass::Other;
}

/** Local signer: outbounds are not Preferred. Live macpro2 after
 *  9ceffddf still 1 body / ~46s because ClassifyMsghandPeer treated
 *  every addrman outbound as Preferred and skip waited for GETDATA
 *  already in m_msg_process_queue. */
[[nodiscard]] inline bool MsghandTreatAsOutboundPreferred(
    bool local_signer,
    bool manual_or_outbound)
{
    if (local_signer) return false;
    return manual_or_outbound;
}

/** Live GETDATA: still in the process queue or unconsumed getdata
 *  requests. Sticky "ever fetched" must not be this — miners that
 *  GETDATA once would stay Preferred forever. */
[[nodiscard]] inline bool MsghandPreferLiveGetData(
    bool queued_getdata,
    bool inflight_getdata_requests)
{
    return queued_getdata || inflight_getdata_requests;
}

/** Only peers that advertised ARCHIVE/MIRROR. Live macpro2 2026-08-16T16:33:
 *  treating every outbound as this drained historical BLOCK to addrman
 *  peers at height 185000 (sent_block≈50KB) while nyc1 inbound mirror
 *  got the same ~50KB and 1 body / ~46s. `manual_or_outbound` is kept so
 *  call sites stay explicit; it must not grant serve-target status. */
[[nodiscard]] inline bool MsghandPeerIsArchiveServeTarget(
    bool manual_or_outbound,
    bool archive_or_mirror_service)
{
    (void)manual_or_outbound;
    return archive_or_mirror_service;
}

/** Peers in a declared MatMul chain role may receive and request chain
 * inventory. This does not make a CONSENSUS peer an archive BLOCK-serve
 * priority target or an authorized inbound block source. */
[[nodiscard]] inline bool MsghandPeerMayReceiveChainInventory(
    bool archive_or_mirror_service,
    bool matmul_consensus_service)
{
    return archive_or_mirror_service || matmul_consensus_service;
}

/** GETHEADERS/GETBLOCKS from an archive, mirror, or consensus peer ask this
 * node to serve chain inventory; they do not ingest an untrusted chain. Keep
 * the non-authority control-message filter for peers outside those roles, but
 * do not strand a trusted mirror or independent consensus verifier. */
[[nodiscard]] inline bool MsghandDropNonAuthorityControlMessage(
    bool restrict_non_authority,
    bool is_chain_service_peer,
    bool is_chain_inventory_request)
{
    if (!restrict_non_authority) return false;
    return !(is_chain_service_peer && is_chain_inventory_request);
}

/** Only archive/GPU GETDATA is Preferred / sets the serve-pending latch.
 *  Miner GETDATA in the same latch put 100 miner fetches in Preferred
 *  with the archive (live 1 BLOCK / ~45s). */
[[nodiscard]] inline bool MsghandPreferArchiveLiveGetData(
    bool live_getdata,
    bool is_archive_serve_target)
{
    return live_getdata && is_archive_serve_target;
}

/** Local signer: msghand leaves archive/mirror *block* GETDATA queued for
 *  ArchiveBlockServe. TX GETDATA stays on msghand. Miner GETDATA is never
 *  skipped (1-BLOCK-per-visit). If the worker is not running, msghand is
 *  the fallback serve path. */
[[nodiscard]] inline bool MsghandSkipArchiveBlockGetData(
    bool local_signer,
    bool archive_serve_worker_running,
    bool is_archive_serve_target)
{
    return local_signer && archive_serve_worker_running &&
           is_archive_serve_target;
}

/** ArchiveBlockServe wait bounds.
 *  Busy: TRY_LOCK(cs_main) failed (ConnectTip / other holders). Wait on
 *  WaitCsMainReleasedForMatMulRecompute so ExactReplay's CsMainScopedRelease
 *  wakes the worker immediately; 250ms is only the poll fallback when the
 *  holder is not ExactReplay (ConnectTip does not notify). Pending/Idle are
 *  GETDATA-queue waits, not ExactReplay. */
static constexpr auto ARCHIVE_BLOCK_SERVE_WAIT_BUSY{std::chrono::milliseconds{250}};
static constexpr auto ARCHIVE_BLOCK_SERVE_WAIT_PENDING{std::chrono::milliseconds{10}};
static constexpr auto ARCHIVE_BLOCK_SERVE_WAIT_IDLE{std::chrono::milliseconds{50}};

/** Local signer: drop non-archive BLOCK/HEADERS ingest while any
 *  archive GETDATA is waiting. Outbound miners too — live signer still
 *  connected tip from addrman peers (b-mmverify ~45%) during nyc1
 *  catch-up. Miner GETDATA does not exempt that miner. */
[[nodiscard]] inline bool TrustedSignerDropMinerIngestWhileGetData(
    bool local_signer,
    bool getdata_pending,
    bool this_inbound,
    bool this_manual,
    bool this_is_archive_serve_target)
{
    (void)this_inbound;
    (void)this_manual;
    (void)getdata_pending;
    if (!local_signer) return false;
    if (this_is_archive_serve_target) return false;
    return true;
}

/** A preferred peer (GPU addnode, outbound, or any inbound on a local
 *  signer) is still in VERSION/V2. */
[[nodiscard]] inline bool PreferredPeerHandshakePending(
    bool handshake_complete,
    bool manual_or_outbound,
    bool local_signer)
{
    if (handshake_complete) return false;
    return manual_or_outbound || local_signer;
}

/** Do not SendMessages (BLOCK/addrv2) to fully-connected miner inbounds
 *  while a preferred peer is still handshaking. Live signer 2026-08-16:
 *  b-msghand ~84% serving inbounds, archive recv=0 until 60s timeout.
 *
 *  Never skip the archive we are protecting: after VERSION it is a
 *  fully-connected inbound, and miners handshake continuously, so the
 *  four-argument form skipped SendMessages to archives forever (GETDATA
 *  replies aged out, 3×90s, disconnect GPU). `this_peer_needs_serve` is
 *  GETDATA queued or a sticky block-fetcher inbound. */
[[nodiscard]] inline bool SkipFullyConnectedInboundDuringPreferredHandshake(
    bool preferred_handshake_pending,
    bool this_peer_inbound,
    bool this_peer_handshake_complete,
    bool this_peer_manual,
    bool this_peer_needs_serve = false)
{
    if (!preferred_handshake_pending) return false;
    if (this_peer_needs_serve) return false;
    if (!this_peer_inbound || this_peer_manual) return false;
    return this_peer_handshake_complete;
}

/** Do not ProcessMessages non-archive peers while we must serve an
 *  archive or while a trusted mirror is catching up to the GPU frontier.
 *  Must skip outbound miners too: ClassifyMsghandPeer still puts every
 *  outbound in Preferred, and the inbound-only skip left addrman
 *  GETDATA on the signer draining BLOCK under cs_main (live 46s/block
 *  after bd3f6b5f). Handshake and ARCHIVE/MIRROR still run. An idle signer
 *  must resume its bounded Other visits so verifier PING/GETHEADERS are not
 *  starved; the separate ingest filter still rejects their block data.
 *  A trusted mirror must continue reading an operator-selected manual peer:
 *  its ingest filter already treats that peer as an explicit catch-up body
 *  source, and skipping it here strands followed-chain recovery forever. */
[[nodiscard]] inline bool SkipMinerProcessMessagesDuringArchiveGetData(
    bool local_signer,
    bool archive_getdata_pending,
    bool trusted_mirror_catch_up,
    bool this_peer_inbound,
    bool this_peer_manual,
    bool this_peer_handshake_complete,
    bool this_is_archive_serve_target)
{
    (void)this_peer_inbound;
    const bool skip_now{
        (local_signer && archive_getdata_pending) || trusted_mirror_catch_up};
    if (!skip_now) return false;
    if (this_is_archive_serve_target) return false;
    if (trusted_mirror_catch_up && this_peer_manual) return false;
    if (!this_peer_handshake_complete) return false;
    return true;
}

/** Keep a GPU/frontier body source after GETDATA timeouts. Live nyc1
 *  2026-08-16: 3×90s disconnected peer=1027; later behind=1 dropped
 *  peer=1433 because IsSignedFrontierCatchUp requires behind>=2.
 *  Last GPU/frontier source is kept regardless of that flag. */
[[nodiscard]] inline bool KeepCatchupSourceOnDownloadTimeout(
    bool signed_frontier_catch_up,
    bool persistent_timeout,
    bool last_gpu_or_frontier_source)
{
    // Keep the last GPU even when IsSignedFrontierCatchUp is false
    // (that helper requires behind>=2 and followed_ahead>=2). Live nyc1
    // 2026-08-16T16:33:38Z disconnected peer=1433 at behind=1.
    if (last_gpu_or_frontier_source) {
        return true;
    }
    return signed_frontier_catch_up && !persistent_timeout;
}

/** Archive msghand skip while bodies lag the GPU followed headers, not
 *  only while signed-frontier blocks_behind>=2. Live nyc1 2026-08-16
 *  after 190666: behind=0 so skip died, 148 miners pegged b-msghand,
 *  suffix headers sat at 190779 with have_data_unconnected. Capped
 *  FollowedChainAhead is 0 at the frontier; pass uncapped tip-extending
 *  ahead. */
[[nodiscard]] inline bool IsTrustedMirrorMsghandCatchUp(
    bool trusted_mirror,
    bool configured,
    int32_t blocks_behind,
    int followed_ahead_uncapped)
{
    return trusted_mirror && configured &&
           (blocks_behind > 0 || followed_ahead_uncapped > 0);
}

/** GPU-attestor body without local quorum: persist, GETMMATTEST, do not
 *  HEADER_ONLY-drop (live re-getdata then 102s timeout). Connect only
 *  once attestation covers the hash. */
[[nodiscard]] inline bool TrustedMirrorRetainGpuBodyAwaitingAttestation(
    bool trusted_mirror,
    bool from_gpu_attestor,
    bool has_quorum)
{
    return trusted_mirror && from_gpu_attestor && !has_quorum;
}

/** Retry delay after retaining a GPU body that still lacks quorum.
 *  WaitTimeout (60s) was the live 34–60s/block crawl when MMATTEST
 *  RefreshRetry(0) missed. 2s is past the 1Hz retain livelock. */
static constexpr auto GPU_RETAIN_ATTESTATION_RETRY{std::chrono::seconds{2}};

/** CPU ExactReplay is the skip gate only when a valid GPU attestation
 *  already covers the hash (in-memory quorum or signed-frontier
 *  ancestry). Catch-up height is not attestation; unattested hashes
 *  still replay. */
[[nodiscard]] inline bool SkipExactReplayForGpuAttestation(
    bool has_valid_gpu_attestation)
{
    return has_valid_gpu_attestation;
}

/** GETHEADERS serve gate. Bitcoin compared nChainWork to nMinimumChainWork.
 *  Using only stale nAuthenticatedChainWork left an ExactReplay-valid
 *  attestor returning empty HEADERS, so CPU archives could not catch up.
 *  Serve when the peer has Download permission, the active tip has a
 *  configured attestation quorum, or claimed chain work meets the minimum. */
[[nodiscard]] inline bool MayServeGetHeaders(
    bool download_permission,
    bool tip_has_quorum,
    bool chain_work_meets_minimum)
{
    return download_permission || tip_has_quorum || chain_work_meets_minimum;
}

/** CPU seeds must keep pulling headers from a GPU attestor after the
 *  VERSION height. A one-shot BestKnown seed at connect must not stop
 *  GETHEADERS for blocks the attestor mints later. */
[[nodiscard]] inline bool TrustedMirrorShouldRequestAuthorityHeaders(
    bool gpu_authority,
    int32_t tip_height,
    int32_t target_height)
{
    if (tip_height < target_height) return true;
    return gpu_authority && tip_height >= 0;
}

/** Archives connected to a GPU attestor (1-of-1 or M-of-N): only those
 *  GPU nodes may deliver inbound BLOCK/HEADERS. Everyone else is
 *  outbound-only (they may fetch blocks from this node). That keeps
 *  archives from spending traffic/CPU on ExactReplay they cannot run.
 *
 *  Pass `trusted_mirror` true for a trusted-mode archive **or** a
 *  consensus node with a local signing key (the attestor). Random inbound
 *  miner BLOCK/HEADERS must not steal ExactReplay from that GPU.
 *
 *  `authority_only_inbound` is true whenever this node is in trusted-GPU
 *  mode (configured keys / trusted mirror / local signer), including
 *  strict -connect. The live check must not take cs_main: taking the lock
 *  per miner addrv2/inv/headers pegged msghand CPU. */
[[nodiscard]] inline bool TrustedMirrorIgnoreNonAuthorityInboundBlock(
    bool trusted_mirror,
    bool this_peer_is_gpu_authority,
    bool authority_only_inbound,
    bool this_inbound = true)
{
    if (!this_inbound) return false;
    return trusted_mirror && !this_peer_is_gpu_authority &&
           authority_only_inbound;
}

/** Solicited catch-up bodies: GPU (either direction) or OUR outbound
 *  archive/mirror. Inbound from anyone else — including an archive
 *  service bit — is dropped before deserialize. An inbound miner
 *  answering GETDATA is not the catch-up path. */
[[nodiscard]] inline bool TrustedMirrorMayAcceptPeerBlockBody(
    bool this_gpu,
    bool this_inbound,
    bool this_archive_or_mirror)
{
    if (this_gpu) return true;
    if (!this_inbound && this_archive_or_mirror) return true;
    return false;
}

/** A valid configured-signer attestation can arrive before its header. In
 *  that case the node asks the same peer for headers, so the inbound filter
 *  may admit the single request-bound HEADERS response. The caller proves the
 *  response is unexpired, contiguous from a known parent, ends at the signed
 *  hash, and resolves to the signed height. It never authorizes BLOCK, INV,
 *  CMPCTBLOCK, or BLOCKTXN ingest. */
[[nodiscard]] inline bool TrustedMirrorMayAcceptPeerBlockMessage(
    bool this_gpu,
    bool this_inbound,
    bool this_archive_or_mirror,
    bool signed_header_response,
    bool is_headers)
{
    return TrustedMirrorMayAcceptPeerBlockBody(
               this_gpu, this_inbound, this_archive_or_mirror) ||
           (signed_header_response && is_headers);
}

/** Match the one-shot response to an MMATTEST-triggered GETHEADERS request.
 *  A public signer attestation is replayable, so neither a timer nor peer
 *  identity alone is authority for arbitrary header ingestion. */
[[nodiscard]] inline bool TrustedMirrorSignedHeaderResponseMatches(
    bool grant_pending,
    bool unexpired,
    bool chain_contiguous,
    bool ends_at_attested_hash,
    int32_t attested_height,
    int32_t connected_height)
{
    return grant_pending && unexpired && chain_contiguous &&
           ends_at_attested_hash && attested_height >= 0 &&
           connected_height == attested_height;
}

/** Unknown quorum-signed hashes remain valid header catch-up targets. A
 *  partial M-of-N signature set is history, not live frontier authority. Once
 *  an operator marks a known index failed, its quorum provenance is likewise
 *  retired from the usable catch-up high-water mark. */
[[nodiscard]] inline bool TrustedMirrorAttestedFrontierHintUsable(
    bool hash_present,
    bool index_known,
    bool index_failed)
{
    return hash_present && (!index_known || !index_failed);
}

/** Non-GPU peers may GETDATA from a trusted mirror only once it is no
 *  longer catching up to the signed frontier. Live nyc1 2026-08-16:
 *  serving miner GETDATA during catch-up produced 2.3MB BLOCK replies
 *  and pegged msghand at 94% so GPU bodies aged out.
 *  Sibling ARCHIVE/MIRROR peers are the exception: they must be able to
 *  fetch bodies this node already has while we still catch up to the GPU. */
[[nodiscard]] inline bool TrustedMirrorMayServeNonAuthorityGetData(
    bool this_peer_is_gpu_authority,
    bool catching_up_behind_frontier,
    bool this_archive_or_mirror = false)
{
    if (this_peer_is_gpu_authority) return true;
    if (this_archive_or_mirror) return true;
    return !catching_up_behind_frontier;
}

/** GPU attestor is the body source even if VERSION omitted NODE_NETWORK.
 *  Live archives 2026-08-16: CanServeBlocks gated getdata off after
 *  handshake when services were empty / NETWORK_LIMITED-only.
 *  Handshake-incomplete addnode (bytesrecv=0, startingheight=-1) must
 *  not occupy the only getdata slot. */
[[nodiscard]] inline bool TrustedMirrorGpuMayServeBlocks(
    bool gpu_authority,
    bool has_network_service,
    bool version_handshake_complete = true)
{
    if (!version_handshake_complete) return false;
    return gpu_authority || has_network_service;
}

/** Root-first must not delete a fresh GETDATA because a second peer is
 *  eligible as a parallel owner. Live nyc1 2026-08-16: MayDuplicate
 *  (owners<2) called RemoveBlockRequest(nullopt); the GPU BLOCK then
 *  arrived unsolicited (forceProcessing=false) and was ticket-dropped. */
[[nodiscard]] inline bool ShouldDropInFlightForRootFirstRerequest(
    bool already_requested,
    bool all_owners_stale)
{
    return already_requested && all_owners_stale;
}

/** Covered HAVE_DATA sitting one height above tip must not freeze the
 *  16-wide GPU window (live 1-block/min: have_data_unconnected return).
 *  Unattested unconnected bodies still halt descendant fetch. */
[[nodiscard]] inline bool TrustedMirrorKeepFetchingCoveredUnconnected(
    bool signed_frontier_catch_up,
    bool unconnected_has_gpu_attestation)
{
    return signed_frontier_catch_up && unconnected_has_gpu_attestation;
}

/** Download timeout for a preferred archive/manual source during
 *  signed-frontier catch-up. Must exceed default -matmultrustedwaitms
 *  (60s) plus a margin: a busy signer/archive holding cs_main for
 *  ExactReplay cannot serve getdata in the generic 15s catch-up window.
 *  90s is only for a handshake-complete GPU (manual/noban). Others
 *  keep 15s. */
[[nodiscard]] inline std::chrono::seconds SignedFrontierPreferredCatchUpTimeout(
    std::chrono::milliseconds wait_timeout)
{
    const auto wait_s{
        std::chrono::duration_cast<std::chrono::seconds>(wait_timeout)};
    constexpr auto kMin{std::chrono::seconds{15}};
    constexpr auto kMargin{std::chrono::seconds{30}};
    if (wait_s < kMin) return kMin;
    return wait_s + kMargin;
}

/** 90s catch-up timeout: operator GPU/noban whose VERSION still shows
 *  bodies past our active tip. Hung -connect (starting_height=-1) and
 *  stale-handshake archives we have climbed past keep 15s so a behind
 *  sibling cannot pin the 1-wide slot for 90s. */
[[nodiscard]] inline bool SignedFrontierCatchUpUsesGpuTimeout(
    bool manual_or_noban,
    bool version_handshake_complete,
    int starting_height = std::numeric_limits<int>::max(),
    int active_tip_height = std::numeric_limits<int>::min())
{
    if (!manual_or_noban || !version_handshake_complete) return false;
    return starting_height > active_tip_height;
}

/** 180s inflight reclaim for GPU catch-up: handshake-complete
 *  manual/noban only. A VERSION-empty addnode must not keep a 180s
 *  pipeline while outbound archives could serve tip+1. */
[[nodiscard]] inline bool KeepGpuSignedFrontierInFlightPipeline(
    bool signed_frontier_catch_up,
    bool manual_or_noban,
    bool version_handshake_complete)
{
    return signed_frontier_catch_up && manual_or_noban &&
           version_handshake_complete;
}

struct AttestedFrontierHint {
    uint256 hash{};
    int32_t height{-1};
};

[[nodiscard]] std::optional<int32_t> HighestAttestedHeight();
[[nodiscard]] std::optional<int32_t> AuthorityPeerTipHint();
[[nodiscard]] std::optional<uint256> AuthorityPeerTipHintHash();
[[nodiscard]] std::vector<AttestedFrontierHint> AttestedFrontierHints();
/** All quorum hashes at a height stay in the hint window (not last-writer). */
/** Raw high-water: max(highest attested, peer tip hint), if either known. */
[[nodiscard]] std::optional<int32_t> AuthorityAttestedFrontier();
/** Record a threshold-confirmed frontier. Production callers must establish
 *  HasQuorum first; direct test callers use this to inject modeled quorum. */
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
    //! HAVE_DATA or retained GPU body on the followed (extends-active-tip)
    //! chain. Live 2026-08-16: after GPU retain, GETMMATTEST was
    //! RejectAboveFrontier because the archive's signed frontier lags the
    //! GPU suffix. Asking the GPU to attest a body it just served is the
    //! intended work. Park still wins.
    bool followed_body_awaiting_attestation{false};
    //! GPU-signed frontier hash itself. Coverage for the ancestor suffix
    //! cannot be fetched if this hash is RejectAboveFrontier.
    bool is_signed_frontier_hash{false};
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
    if (v.short_tip_reorg || v.on_recent_active_ancestor ||
        v.followed_body_awaiting_attestation || v.is_signed_frontier_hash) {
        // Short tip-race reorg, the active tip / last few ancestors so a
        // linear chain can populate getmatmulattestedtip, a followed
        // HAVE_DATA / retained GPU body, or the signed-frontier hash
        // whose quorum covers the ancestor suffix. Park still wins.
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
