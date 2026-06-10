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
#include <optional>

class CChainParams;
class ValidationSignals;

static constexpr bool DEFAULT_CHECKPOINTS_ENABLED{true};
static constexpr auto DEFAULT_MAX_TIP_AGE{24h};
//! DS-3 compatibility default: current shipped assumeutxo snapshots do not yet carry shielded pins.
//! Keep bootstrap usable by default, while allowing strict operators to opt out with
//! -allowunpinnedshieldedsnapshot=0 until pinned snapshots are shipped.
static constexpr bool DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT{true};

namespace kernel {

enum class MatMulValidationMode {
    CONSENSUS,
    ECONOMIC,
    SPV,
};

//! What a node does when an incoming branch would reorg the active chain deeper
//! than the deep-reorg threshold (-maxreorgdepthwarn, default = consensus
//! nMaxReorgDepth).
//!
//! WARN (default, Nakamoto-safe): emit a loud warning + RPC/notification and
//!   still follow the most-work chain. This buys operators/exchanges response
//!   time WITHOUT introducing any finality assumption, so it can never split the
//!   network: every honest node, regardless of how it was partitioned, still
//!   converges on the single most-work chain.
//!
//! PARK (opt-in, -parkdeepreorg=1): refuse to auto-switch to the deeper branch
//!   and stay on the current tip pending operator action, while still tracking
//!   the branch in the block index. This protects a single node from a silent
//!   deep rewrite, but it is a LOCAL FINALITY assumption: see the split-risk
//!   memo at the call site. It is per-node, non-consensus, and OFF by default so
//!   the network's default behavior remains pure Nakamoto consensus.
enum class DeepReorgAction {
    WARN,
    PARK,
};

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
    //! DS-3 compatibility gate: optionally refuse to load an assumeutxo snapshot whose shielded section has no
    //! consensus pin (AssumeutxoData.shielded_state_commitment) for its height. The shielded section
    //! (pool balance + nullifier set + commitment tree) is attacker-supplied and otherwise unvalidated,
    //! so an unpinned shielded snapshot can seed a double-spend. Default true preserves shipped snapshot
    //! bootstrap compatibility; set false (-allowunpinnedshieldedsnapshot=0) to require pinned snapshots.
    bool allow_unpinned_shielded_snapshot{DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT};
    //! Action taken when a candidate branch would reorg deeper than the
    //! deep-reorg threshold. Default WARN keeps pure Nakamoto consensus (no
    //! split risk); PARK is an opt-in per-node finality assumption.
    DeepReorgAction deep_reorg_action{DeepReorgAction::WARN};
    //! Operator override for the deep-reorg threshold, in blocks. When unset the
    //! consensus value nMaxReorgDepth is used (if configured for the chain).
    //! Setting this lets an operator warn/park at a shallower depth than the
    //! chain default without recompiling.
    std::optional<uint32_t> max_reorg_depth_warn{};
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
