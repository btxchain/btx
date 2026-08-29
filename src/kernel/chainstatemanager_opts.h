// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CHAINSTATEMANAGER_OPTS_H
#define BITCOIN_KERNEL_CHAINSTATEMANAGER_OPTS_H

#include <kernel/notifications_interface.h>

#include <arith_uint256.h>
#include <dbwrapper.h>
#include <script/sigcache.h>
#include <txdb.h>
#include <uint256.h>
#include <util/time.h>

#include <cstdint>
#include <functional>
#include <limits>
#include <optional>

class CChainParams;
class ValidationSignals;

static constexpr bool DEFAULT_CHECKPOINTS_ENABLED{true};
// IBD-LIVE-01 (audit 2026-08-27): BTX blocks may legitimately remain unchanged
// for more than 24 hours while the network works through a high-cost MatMul
// candidate or a coordinated chain recovery. With a 24h default, every node
// restarting on that valid tip re-enters IBD -- which also disarms the cadence
// hold (see in_ibd below), exempts the unauthenticated-header-lead cap, and
// feeds the mining chain guard. Observed live 2026-08-27: the GPU signer
// reported initialblockdownload=true on a 55h-old canonical tip while peers
// were ahead. Keep such nodes in normal relay mode by default; operators can
// still select a stricter freshness policy with -maxtipage. Node policy only:
// no change to validity, ExactReplay, chainwork, fork choice, or timestamps.
static constexpr auto DEFAULT_MAX_TIP_AGE{30 * 24h};
// Two workers provided the best end-to-end result in BTX's cold-restart
// persisted-UTXO benchmark. More workers remain available through
// -prevoutfetchthreads, but can regress fast storage through scheduling and
// LevelDB lock contention.
static constexpr int32_t DEFAULT_PREVOUTFETCH_THREADS{2};
//! Fail closed for shielded assumeutxo state unless the snapshot height has a
//! consensus shielded-state pin, or the operator explicitly opts into trusting an
//! unpinned shielded snapshot with -allowunpinnedshieldedsnapshot=1.
static constexpr bool DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT{false};

namespace kernel {

enum class MatMulValidationMode {
    CONSENSUS,
    //! Operator-configured M-of-N trust in signed ExactReplay attestations.
    //! This mode performs every ordinary block/body/script check but delegates
    //! the expensive Profile-1 replay verdict to explicitly configured archive
    //! validators. It is not independent consensus validation.
    TRUSTED,
    //! 0.34 discovery / introduction node. ADDR (and unauthenticated header
    //! gossip) only: not ExactReplay, not a pin skip, not GETMMATTEST, not a
    //! chain-tip oracle. Public DNS/addnode hosts should run this so they stop
    //! being MatMul authority and stop fanning GETMMATTEST into GPU attestors.
    //! Archives still follow GPU nodes via the pin; this host only points at
    //! other nodes.
    RELAY,
    ECONOMIC,
    SPV,
};

[[nodiscard]] inline constexpr bool MatMulModeIsChainAuthority(MatMulValidationMode m)
{
    return m == MatMulValidationMode::CONSENSUS ||
           m == MatMulValidationMode::TRUSTED;
}

[[nodiscard]] inline constexpr bool MatMulModeIsDiscoveryRelay(MatMulValidationMode m)
{
    return m == MatMulValidationMode::RELAY;
}

[[nodiscard]] inline constexpr const char* MatMulValidationModeName(MatMulValidationMode m)
{
    switch (m) {
    case MatMulValidationMode::CONSENSUS: return "consensus";
    case MatMulValidationMode::TRUSTED: return "trusted";
    case MatMulValidationMode::RELAY: return "relay";
    case MatMulValidationMode::ECONOMIC: return "economic";
    case MatMulValidationMode::SPV: return "spv";
    }
    return "unknown";
}

//! What a node does when an incoming branch would reorg the active chain deeper
//! than the configured deep-reorg threshold.
//!
//! WARN (-parkdeepreorg=0): emit a loud warning + RPC/notification and still
//!   follow the most-work chain once automated hysteresis/extra-work rules are
//!   satisfied. This avoids a manual-intervention split while still making
//!   private-branch behavior visible.
//!
//! PARK: refuse to auto-switch to the deeper branch and stay on the current
//!   tip pending explicit unpark/reconsider, while still tracking the branch
//!   in the block index. The default EMERGENCY profile PARKs at depth 6
//!   (2026-08-10/11 rented-hashpower 151-block / 8-block rewrites). Override
//!   with -parkdeepreorg=0 to follow most-work with a warning instead.
enum class DeepReorgAction {
    WARN,
    PARK,
};

enum class ReorgProtectionProfile {
    STANDARD,
    ARCHIVE,
    BALANCED,
    STRICT,
    EMERGENCY,
};

struct ReorgProtectionProfileSettings {
    DeepReorgAction action{DeepReorgAction::WARN};
    uint32_t warn_depth{3};
    uint32_t park_depth{std::numeric_limits<uint32_t>::max()};
    uint32_t finality_depth{12};
    uint32_t hysteresis_depth{std::numeric_limits<uint32_t>::max()};
    uint32_t hysteresis_work_margin{0};
};

inline constexpr uint32_t REORG_PROTECTION_DEPTH_DISABLED{std::numeric_limits<uint32_t>::max()};

//! Immediate live-tip extension allowance while cadence hold is armed.
//! Stay strictly below EMERGENCY park_depth (6) so PARK still owns deep reorgs.
inline constexpr uint32_t DEFAULT_CADENCE_BURST_MAX{3};

//! Competing unauthenticated HEADER_ONLY towers may not grow farther ahead
//! of the active tip than emergency local-finality. Followed-chain headers,
//! IBD, and attested / signed-frontier headers are exempt (cadence hold
//! still paces bodies on a live-tip dump). Matches discovery RECENT_HEIGHT_LAG.
inline constexpr int MAX_UNAUTHENTICATED_HEADER_LEAD{72};

inline constexpr ReorgProtectionProfileSettings GetReorgProtectionProfileSettings(ReorgProtectionProfile profile)
{
    switch (profile) {
    case ReorgProtectionProfile::STANDARD:
        return {
            .action = DeepReorgAction::WARN,
            .warn_depth = 3,
            .park_depth = REORG_PROTECTION_DEPTH_DISABLED,
            .finality_depth = 12,
            .hysteresis_depth = 0,
            .hysteresis_work_margin = 2,
        };
    case ReorgProtectionProfile::ARCHIVE:
        return {
            .action = DeepReorgAction::WARN,
            .warn_depth = 72,
            .park_depth = REORG_PROTECTION_DEPTH_DISABLED,
            .finality_depth = 72,
            .hysteresis_depth = 0,
            .hysteresis_work_margin = 2,
        };
    case ReorgProtectionProfile::BALANCED:
        return {
            .action = DeepReorgAction::WARN,
            .warn_depth = 12,
            .park_depth = REORG_PROTECTION_DEPTH_DISABLED,
            .finality_depth = 48,
            .hysteresis_depth = 0,
            .hysteresis_work_margin = 2,
        };
    case ReorgProtectionProfile::STRICT:
        return {
            .action = DeepReorgAction::WARN,
            .warn_depth = 3,
            .park_depth = REORG_PROTECTION_DEPTH_DISABLED,
            .finality_depth = 12,
            .hysteresis_depth = 0,
            .hysteresis_work_margin = 2,
        };
    case ReorgProtectionProfile::EMERGENCY:
        // Automatic deep-reorg finality (default profile).
        //
        // Rented-hashpower reorg attacks were executed against mainnet on
        // 2026-08-10/11 (151-block and 8-block rewrites, a third prepared).
        // WARN-only meant every operator had to park by hand, in coordination,
        // at each incident. PARK at 6 makes the refusal automatic and
        // network-wide: ordinary 1-5 block races still settle by work, while a
        // deep rewrite is refused and left for an operator decision.
        // Override with -parkdeepreorg=0 / -maxreorgdepthpark=<n>.
        return {
            .action = DeepReorgAction::PARK,
            .warn_depth = 3,
            .park_depth = 6,
            .finality_depth = 72,
            .hysteresis_depth = 0,
            .hysteresis_work_margin = 2,
        };
    }
    return {};
}

//! Whether ActivateBestChain should park a candidate instead of connecting it.
//! Default EMERGENCY: PARK, park_depth=6. recovery_escape is
//! IsAutomaticReorgRecoveryCandidate || IsAttestedAbandonForkCandidate.
//! A 151-block unattested rewrite parks; a 1–5 block race still connects.
//! IsAutomaticReorgRecoveryCandidate only fires when a recovery record was
//! armed (WorkBasedReorgRecoveryMayArm). Those two predicates are mutually
//! exclusive on purpose: parked depth is operator-only on consensus miners
//! (dump-and-run). Trusted mirrors may still IsAttestedAbandonForkCandidate.
[[nodiscard]] inline constexpr bool DeepReorgShouldPark(
    DeepReorgAction action,
    uint32_t park_depth,
    int reorg_depth,
    bool recovery_escape)
{
    return action == DeepReorgAction::PARK &&
           park_depth != REORG_PROTECTION_DEPTH_DISABLED &&
           reorg_depth > static_cast<int>(park_depth) &&
           !recovery_escape;
}

//! Work-based automatic reorg recovery (CONSENSUS nAuthenticatedChainWork)
//! arms only for 1 <= depth <= park_depth. PARK fires on depth > park_depth.
//! Do not extend this window: a dump-and-run rewrite that ExactReplays
//! itself would then auto-unpark. Consensus miners unpark parked branches
//! with reconsiderblock. Trusted mirrors still have attested abandon.
[[nodiscard]] inline constexpr bool WorkBasedReorgRecoveryMayArm(
    int reorg_depth,
    uint32_t park_depth)
{
    return park_depth != REORG_PROTECTION_DEPTH_DISABLED &&
           reorg_depth > 0 &&
           reorg_depth <= static_cast<int>(park_depth);
}

//! Highest connected ancestor whose nTime is not in the future. After a
//! future-stamped burst is partially connected, walking back keeps the
//! height horizon pinned to the last wall-clock-honest tip (anti-drip).
template <typename Node>
[[nodiscard]] inline const Node* CadenceHoldOrigin(const Node* tip, int64_t now)
{
    const Node* p = tip;
    const Node* last = tip;
    while (p != nullptr && static_cast<int64_t>(p->nTime) > now) {
        last = p;
        p = p->pprev;
    }
    return p != nullptr ? p : last;
}

//! Highest height this node will connect or GETDATA at wall-clock `now`.
//! extra = max(0, now - origin_time) / spacing so honest 90s progress
//! raises the horizon one block per interval.
[[nodiscard]] inline constexpr int CadenceHoldAllowedHeight(
    int origin_height,
    int64_t origin_time,
    int64_t now,
    int64_t spacing,
    uint32_t burst_max)
{
    if (burst_max == 0 || spacing <= 0) {
        return std::numeric_limits<int>::max();
    }
    const int64_t extra{now > origin_time ? (now - origin_time) / spacing : 0};
    const int64_t allowed{static_cast<int64_t>(origin_height) +
                          static_cast<int64_t>(burst_max) + extra};
    if (allowed >= std::numeric_limits<int>::max()) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(allowed);
}

//! Local cadence hold: live tip, candidate jumps more than burst_max beyond
//! what wall clock explains at nPowTargetSpacing. PARK owns reorg_depth >
//! park_depth (do not also hold those; they are parked). IBD / stale tip
//! (monotonic last-connect, not NTP-inflated unix first-seen) /
//! recovery_escape disarm so partition catch-up still runs at body-download
//! speed. recovery_escape is CadenceHoldQuorumMayEscape (trusted-mirror pin
//! follow only). Consensus miners do not escape an attested dump.
[[nodiscard]] inline constexpr bool CadenceHoldShouldHold(
    uint32_t burst_max,
    int64_t live_window_s,
    int64_t spacing_s,
    int64_t now,
    int64_t origin_time,
    int origin_height,
    int candidate_height,
    int fork_depth,
    uint32_t park_depth,
    bool in_ibd,
    bool recovery_escape)
{
    if (burst_max == 0 || in_ibd || recovery_escape) return false;
    if (park_depth != REORG_PROTECTION_DEPTH_DISABLED &&
        fork_depth > static_cast<int>(park_depth)) {
        return false;
    }
    if (live_window_s >= 0 && now - origin_time > live_window_s) return false;
    return candidate_height > CadenceHoldAllowedHeight(
               origin_height, origin_time, now, spacing_s, burst_max);
}

//! Work-rate / first-seen dump: height span beyond burst_max arrived in
//! less wall-clock than honest nPowTargetSpacing explains. ASERT reads
//! attacker-chosen nTime; this predicate uses peer first-seen span only.
//! first_seen_span_s < 0 means unknown (headers loaded from disk).
//! Production extra is wall-clock from OUR tip, not dump first-seen.
//! If this predicate is ever OR'd into a hold, the span MUST be body /
//! usable-chain (CadenceUsableFirstSeenSpan), never header arrival.
[[nodiscard]] inline constexpr bool CadenceFirstSeenLooksLikeDump(
    int height_span,
    int64_t first_seen_span_s,
    int64_t spacing_s,
    uint32_t burst_max)
{
    if (burst_max == 0 || spacing_s <= 0 || height_span <= 0) return false;
    if (first_seen_span_s < 0) return false;
    if (height_span <= static_cast<int>(burst_max)) return false;
    const int64_t expected{(static_cast<int64_t>(height_span) -
                            static_cast<int64_t>(burst_max)) *
                           spacing_s};
    return first_seen_span_s < expected;
}

//! Header pre-aging (announce headers slowly, dump bodies later) must
//! not manufacture an old first-seen span. Unknown body (0 / negative)
//! is unknown — do not fall back to header arrival.
[[nodiscard]] inline constexpr int64_t CadenceUsableFirstSeenSpan(
    int64_t header_first_seen_span_s,
    int64_t body_first_seen_span_s)
{
    (void)header_first_seen_span_s;
    return body_first_seen_span_s > 0 ? body_first_seen_span_s : -1;
}

//! Hijack 2.2 CLOSED: production CadenceHoldShouldHold extra is wall-clock
//! from this node's tip / hold anchor. Header-arrival first-seen must not
//! feed it. CadenceFirstSeenLooksLikeDump is diagnostic only — do not OR
//! it into a permanent freeze.
[[nodiscard]] inline constexpr bool CadenceHoldUsesHeaderArrivalAsExtra()
{
    return false;
}

//! Hijack 2.3 ACCEPT-WITH-DOC: after burst_max, extra is +1 per
//! nPowTargetSpacing. A withheld majority trickling at that rate is
//! Nakamoto. Holding it forever would be a finality gadget. Do not
//! "fix" with reseal, header-PoW, or HasQuorum.
[[nodiscard]] inline constexpr bool CadenceHoldHonestTrickleIsNakamoto()
{
    return true;
}

//! Hijack 2.4: idle extra is burst + floor(idle/spacing), never INT_MAX.
//! Empty restart stays extra=0 (fail-closed). Persist first-seen is not
//! 0.34 state; extra=0 is stricter than a dump window.
[[nodiscard]] inline constexpr bool CadenceHoldIdleAllowedIsBounded(
    int allowed_height,
    int tip_height,
    uint32_t burst_max,
    int extra_spacings)
{
    if (burst_max == 0) {
        return allowed_height == std::numeric_limits<int>::max();
    }
    if (allowed_height == std::numeric_limits<int>::max()) return false;
    const int64_t expect{static_cast<int64_t>(tip_height) +
                         static_cast<int64_t>(burst_max) + extra_spacings};
    if (expect >= std::numeric_limits<int>::max()) return false;
    return allowed_height == static_cast<int>(expect);
}

//! Cadence recovery_escape is pin-follow on trusted mirrors only.
//! Consensus miners ExactReplay: an attested withheld dump still holds
//! (ordering: cadence precedes unkeyed quorum connect). PARK still uses
//! IsAttestedAbandonForkCandidate separately.
[[nodiscard]] inline constexpr bool CadenceHoldQuorumMayEscape(
    bool trusted_mirror,
    bool attested_abandon)
{
    return trusted_mirror && attested_abandon;
}

//! assumeutxo / snapshot catch-up toward disk-loaded followed headers
//! is not a withheld dump. Attacker cannot claim snapshot (local
//! chainstate flag). Live-gossip best-header (nTimeReceived > 0) does
//! not disarm — that is the 2.2 / dump path.
[[nodiscard]] inline constexpr bool CadenceHoldSnapshotCatchUpDisarms(
    bool from_snapshot,
    bool best_header_extends_tip,
    bool best_header_loaded_from_disk)
{
    return from_snapshot && best_header_extends_tip &&
           best_header_loaded_from_disk;
}

//! Same-chain HEADER_ONLY suffix of this many blocks is catch-up, not a
//! withheld dump. Cadence would otherwise connect burst_max per ABC and
//! leave a consensus archive frozen while bodies sit on disk (live
//! rtx6000: 423 headers ahead, tip stalled). Competing forks
//! (best_header does not extend the tip) still hold. ExactReplay still
//! runs before every ConnectTip.
[[nodiscard]] inline constexpr bool CadenceHoldFollowedCatchUpDisarms(
    bool best_header_extends_tip,
    int followed_ahead,
    int far_behind_yield = 100)
{
    return best_header_extends_tip && followed_ahead >= far_behind_yield;
}

//! Restart: nTimeReceived and last ConnectTip are empty. Do not treat
//! attacker-chosen nTime as stale (nTime-forged dump-on-restart).
[[nodiscard]] inline constexpr bool CadenceHoldRestartLeavesHoldArmed(
    bool ntime_received_unknown,
    bool last_connect_unknown)
{
    return ntime_received_unknown && last_connect_unknown;
}

//! Historical catch-up IBD: still loading blocks, no tip, or nChainWork
//! below nMinimumChainWork. Distinct from age-only IBD (tip older than
//! -maxtipage). A stalled chain whose tip exceeds -maxtipage looks like
//! IBD after restart even when this node is fully caught up; suppressing
//! INV then hides a unique mined block until someone GETDATAs it. Do not
//! use IsInitialBlockDownload() as the announce/GBT gate — that conflates
//! the two. Fee filter MAX_MONEY may still follow IsInitialBlockDownload
//! so remote age-only IBD remains observable.
[[nodiscard]] inline constexpr bool IbdIsHistoricalCatchUp(
    bool loading_blocks,
    bool has_tip,
    bool sufficient_chainwork)
{
    return loading_blocks || !has_tip || !sufficient_chainwork;
}

[[nodiscard]] inline constexpr bool IbdShouldSuppressBlockAnnounce(
    bool loading_blocks,
    bool has_tip,
    bool sufficient_chainwork)
{
    return IbdIsHistoricalCatchUp(loading_blocks, has_tip, sufficient_chainwork);
}

//! GBT: refuse historical catch-up so a node cannot mine from genesis /
//! mid-reindex. Age-only stale tip (stall recovery) must still be able
//! to mine; announcement is handled separately so mining is not silent.
[[nodiscard]] inline constexpr bool MiningTemplateShouldRefuseIbd(
    bool loading_blocks,
    bool has_tip,
    bool sufficient_chainwork)
{
    return IbdIsHistoricalCatchUp(loading_blocks, has_tip, sufficient_chainwork);
}

//! in_ibd && not historical catch-up ⇒ the only remaining IBD reason is
//! tip nTime older than -maxtipage (default 30 days).
[[nodiscard]] inline constexpr bool IbdIsAgeOnlyStaleTip(
    bool in_ibd,
    bool loading_blocks,
    bool has_tip,
    bool sufficient_chainwork)
{
    return in_ibd &&
           !IbdIsHistoricalCatchUp(loading_blocks, has_tip, sufficient_chainwork);
}

//! Compact-block / NewPoWValidBlock of a newly accepted tip-child.
//! Historical IBD still skips (flood). Age-only and non-IBD relay.
[[nodiscard]] inline constexpr bool MayFastRelayNewTipChild(
    bool extends_active_tip,
    bool loading_blocks,
    bool has_tip,
    bool sufficient_chainwork)
{
    if (!extends_active_tip) return false;
    return !IbdShouldSuppressBlockAnnounce(
        loading_blocks, has_tip, sufficient_chainwork);
}

//! Competing unauthenticated header flood: do not store towers farther
//! than max_lead above the active tip. Followed-chain catch-up / IBD /
//! attested headers return false.
[[nodiscard]] inline constexpr bool UnauthenticatedHeaderLeadExceeded(
    int tip_height,
    int header_height,
    bool extends_active_tip,
    bool attested_or_frontier,
    bool in_ibd,
    int max_lead = MAX_UNAUTHENTICATED_HEADER_LEAD)
{
    if (in_ibd || attested_or_frontier || extends_active_tip) return false;
    if (tip_height < 0 || header_height < 0 || max_lead < 0) return false;
    return header_height > tip_height + max_lead;
}

//! Stop chasing / GETDATA once the stored competing tower has reached
//! max_lead (inclusive). Storage still uses UnauthenticatedHeaderLeadExceeded
//! (`>`) so the last in-window header is indexed.
[[nodiscard]] inline constexpr bool UnauthenticatedHeaderLeadAtCap(
    int tip_height,
    int header_height,
    bool extends_active_tip,
    bool attested_or_frontier,
    bool in_ibd,
    int max_lead = MAX_UNAUTHENTICATED_HEADER_LEAD)
{
    if (in_ibd || attested_or_frontier || extends_active_tip) return false;
    if (tip_height < 0 || header_height < 0 || max_lead < 0) return false;
    return header_height >= tip_height + max_lead;
}

inline const char* ReorgProtectionProfileName(ReorgProtectionProfile profile)
{
    switch (profile) {
    case ReorgProtectionProfile::STANDARD: return "standard";
    case ReorgProtectionProfile::ARCHIVE: return "archive";
    case ReorgProtectionProfile::BALANCED: return "balanced";
    case ReorgProtectionProfile::STRICT: return "strict";
    case ReorgProtectionProfile::EMERGENCY: return "emergency";
    }
    return "unknown";
}

/**
 * An options struct for `ChainstateManager`, more ergonomically referred to as
 * `ChainstateManager::Options` due to the using-declaration in
 * `ChainstateManager`.
 */
struct ChainstateManagerOpts {
    const CChainParams& chainparams;
    fs::path datadir;
    std::optional<int32_t> check_block_index{};
    bool checkpoints_enabled{DEFAULT_CHECKPOINTS_ENABLED};
    //! If set, it will override the minimum work we will assume exists on some valid chain.
    std::optional<arith_uint256> minimum_chain_work{};
    //! If set, it will override the block hash whose ancestors we will assume to have valid scripts without checking them.
    std::optional<uint256> assumed_valid_block{};
    //! If the tip is older than this, IsInitialBlockDownload stays true.
    //! That latch also covers a stalled chain after restart (tip nTime can
    //! be days old while nChainWork is already sufficient). Announce and
    //! GBT use IbdShouldSuppressBlockAnnounce / MiningTemplateShouldRefuseIbd
    //! so age-only IBD is not silent mining.
    std::chrono::seconds max_tip_age{DEFAULT_MAX_TIP_AGE};
    MatMulValidationMode matmul_validation_mode{MatMulValidationMode::CONSENSUS};
    //! Default operator profile: keep the shielded commitment-position index on disk for fast restart and snapshot recovery.
    bool retain_shielded_commitment_index{true};
    //! Audit restored shielded state against historical block data during startup. When the
    //! fast-startup path below is not taken, this controls whether the cross-chain audit runs.
    bool shielded_startup_audit{true};
    //! Zero-downtime restart: when matching persisted shielded state is available, trust it and
    //! skip the full-chain settlement/netting drift sync and the cross-chain audit. Default on;
    //! the persisted snapshot reaching the restore path already had its frontier root/size matched
    //! to the active tip and its commitment index/anchor windows validated, so the skipped audit is
    //! fail-closed (it can only reject, never accept). Set to 0 to force the thorough sync + audit.
    bool fast_shielded_startup{true};
    //! One-shot repair: when set, wipe the on-disk shielded_state directory at startup and force a single
    //! clean full rebuild from local block data. Supported replacement for the manual "move shielded_state
    //! aside" recovery; intended to be passed once (e.g. -resetshieldedstate) then removed.
    bool reset_shielded_state{false};
    //! Opt in to opening nullifiers / commitments / account_registry after
    //! nShieldedPoolDisableHeight. Default off once the active tip is at or
    //! past that height: spends are consensus-invalid, so the stores are not
    //! required. Explorers and indexers pass -shieldedstate=1.
    bool force_shielded_state{false};
    //! DS-3 compatibility gate: optionally allow loading an assumeutxo snapshot whose shielded section has no
    //! consensus pin (AssumeutxoData.shielded_state_commitment) for its height. The shielded section
    //! (pool balance + nullifier set + commitment tree) is attacker-supplied and otherwise unvalidated,
    //! so an unpinned shielded snapshot can seed a double-spend. Default false fails closed; set true
    //! (-allowunpinnedshieldedsnapshot=1) only for explicitly trusted repair/bootstrap material.
    bool allow_unpinned_shielded_snapshot{DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT};
    //! Action taken when a candidate branch would reorg deeper than the
    //! deep-reorg threshold. The struct field defaults to WARN so unit tests
    //! that construct Options without going through FillChainstateManagerArgs
    //! do not park; production args resolve this from
    //! reorg_protection_profile (EMERGENCY → PARK at depth 6). Override with
    //! -parkdeepreorg=0/1.
    DeepReorgAction deep_reorg_action{DeepReorgAction::WARN};
    //! Named reorg/finality policy. EMERGENCY is the default: PARK at depth 6
    //! (dump-and-run defense), warn at 3, hysteresis work margin 2. Other
    //! profiles WARN-only. Override with -reorgprotectionprofile= or
    //! -parkdeepreorg=0.
    ReorgProtectionProfile reorg_protection_profile{ReorgProtectionProfile::EMERGENCY};
    //! Operator override for the deep-reorg threshold, in blocks. When unset the
    //! active reorg protection profile controls the warning depth.
    std::optional<uint32_t> max_reorg_depth_warn{};
    //! Operator override for the local parking threshold, in blocks. When unset
    //! the active reorg protection profile controls the parking depth.
    std::optional<uint32_t> max_reorg_depth_park{};
    //! Operator override for the reported practical local-finality depth. This
    //! is not consensus finality; it is an operator safety signal surfaced by
    //! RPCs and release policy.
    std::optional<uint32_t> local_finality_depth{};
    //! Operator override for shallow-reorg hysteresis. Candidate branches that
    //! would rewrite more than this many blocks must exceed the active tip by
    //! the configured work margin before automatic activation. This is local
    //! fork-choice policy only; blocks remain valid and can become eligible
    //! once they accumulate enough work.
    std::optional<uint32_t> reorg_hysteresis_depth{};
    //! Required extra work margin expressed in current-tip block equivalents.
    //! Zero disables the hysteresis margin.
    std::optional<uint32_t> reorg_hysteresis_work_margin{};
    //! Live-tip burst allowance in blocks. 0 disables. Default 0 so unit
    //! tests that construct Options without ApplyArgsManOptions keep mining
    //! at test speed; production mainnet emergency sets DEFAULT_CADENCE_BURST_MAX
    //! via -cadenceburstmax / ApplyArgsManOptions.
    uint32_t cadence_burst_max{0};
    DBOptions coins_db{};
    CoinsViewOptions coins_view{};
    Notifications& notifications;
    ValidationSignals* signals{nullptr};
    //! Number of script check worker threads. Zero means no parallel verification.
    int worker_threads_num{0};
    //! Number of workers used to prefetch block input prevouts. Zero disables prefetching.
    int32_t prevoutfetch_threads_num{DEFAULT_PREVOUTFETCH_THREADS};
    size_t script_execution_cache_bytes{DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES};
    size_t signature_cache_bytes{DEFAULT_SIGNATURE_CACHE_BYTES};
};

} // namespace kernel

#endif // BITCOIN_KERNEL_CHAINSTATEMANAGER_OPTS_H
