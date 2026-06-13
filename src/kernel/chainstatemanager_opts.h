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
static constexpr auto DEFAULT_MAX_TIP_AGE{24h};
//! Fail closed for shielded assumeutxo state unless the snapshot height has a
//! consensus shielded-state pin, or the operator explicitly opts into trusting an
//! unpinned shielded snapshot with -allowunpinnedshieldedsnapshot=1.
static constexpr bool DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT{false};

namespace kernel {

enum class MatMulValidationMode {
    CONSENSUS,
    ECONOMIC,
    SPV,
};

//! What a node does when an incoming branch would reorg the active chain deeper
//! than the configured deep-reorg threshold.
//!
//! WARN (-parkdeepreorg=0, or a profile such as standard/archive): emit a loud warning +
//!   RPC/notification and still follow the most-work chain. This buys
//!   operators/exchanges response time WITHOUT introducing any finality
//!   assumption, so every honest node, regardless of how it was partitioned,
//!   still converges on the single most-work chain.
//!
//! PARK (default emergency profile, strict profile, or -parkdeepreorg=1): refuse to
//!   auto-switch to the deeper branch and stay on the current tip pending
//!   operator action, while still tracking the branch in the block index. This
//!   protects ordinary nodes from silently following a deep rewrite, but it is
//!   still a LOCAL FINALITY assumption: see the split-risk memo at the call site.
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
};

inline constexpr uint32_t REORG_PROTECTION_DEPTH_DISABLED{std::numeric_limits<uint32_t>::max()};

inline ReorgProtectionProfileSettings GetReorgProtectionProfileSettings(ReorgProtectionProfile profile)
{
    switch (profile) {
    case ReorgProtectionProfile::STANDARD:
        return {
            .action = DeepReorgAction::WARN,
            .warn_depth = 3,
            .park_depth = 12,
            .finality_depth = 12,
        };
    case ReorgProtectionProfile::ARCHIVE:
        return {
            .action = DeepReorgAction::WARN,
            .warn_depth = 72,
            .park_depth = REORG_PROTECTION_DEPTH_DISABLED,
            .finality_depth = 72,
        };
    case ReorgProtectionProfile::BALANCED:
        return {
            .action = DeepReorgAction::PARK,
            .warn_depth = 12,
            .park_depth = 48,
            .finality_depth = 48,
        };
    case ReorgProtectionProfile::STRICT:
        return {
            .action = DeepReorgAction::PARK,
            .warn_depth = 3,
            .park_depth = 12,
            .finality_depth = 12,
        };
    case ReorgProtectionProfile::EMERGENCY:
        return {
            .action = DeepReorgAction::PARK,
            .warn_depth = 3,
            .park_depth = 12,
            .finality_depth = 12,
        };
    }
    return {};
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
    //! If the tip is older than this, the node is considered to be in initial block download.
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
    //! DS-3 compatibility gate: optionally allow loading an assumeutxo snapshot whose shielded section has no
    //! consensus pin (AssumeutxoData.shielded_state_commitment) for its height. The shielded section
    //! (pool balance + nullifier set + commitment tree) is attacker-supplied and otherwise unvalidated,
    //! so an unpinned shielded snapshot can seed a double-spend. Default false fails closed; set true
    //! (-allowunpinnedshieldedsnapshot=1) only for explicitly trusted repair/bootstrap material.
    bool allow_unpinned_shielded_snapshot{DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT};
    //! Action taken when a candidate branch would reorg deeper than the
    //! deep-reorg threshold. BTX's emergency default parks deep private releases
    //! instead of silently following them.
    DeepReorgAction deep_reorg_action{DeepReorgAction::PARK};
    //! Named reorg/finality policy. EMERGENCY is the default while the network
    //! is fragmented: warn at shallow depth and park deeper private releases.
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
    DBOptions coins_db{};
    CoinsViewOptions coins_view{};
    Notifications& notifications;
    ValidationSignals* signals{nullptr};
    //! Number of script check worker threads. Zero means no parallel verification.
    int worker_threads_num{0};
    size_t script_execution_cache_bytes{DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES};
    size_t signature_cache_bytes{DEFAULT_SIGNATURE_CACHE_BYTES};
};

} // namespace kernel

#endif // BITCOIN_KERNEL_CHAINSTATEMANAGER_OPTS_H
