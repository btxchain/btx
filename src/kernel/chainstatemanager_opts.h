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
//! DS-3: production nodes fail-closed on assumeutxo shielded sections with no consensus pin.
static constexpr bool DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT{false};

namespace kernel {

enum class MatMulValidationMode {
    CONSENSUS,
    ECONOMIC,
    SPV,
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
    //! DS-3 fail-closed: refuse to load an assumeutxo snapshot whose shielded section has no
    //! consensus pin (AssumeutxoData.shielded_state_commitment) for its height. The shielded section
    //! (pool balance + nullifier set + commitment tree) is attacker-supplied and otherwise unvalidated,
    //! so an unpinned shielded snapshot can seed a double-spend. Default off = reject unpinned shielded
    //! snapshots; set true (-allowunpinnedshieldedsnapshot) only to bootstrap from a snapshot you trust
    //! out-of-band before its pin is filled in.
    bool allow_unpinned_shielded_snapshot{DEFAULT_ALLOW_UNPINNED_SHIELDED_SNAPSHOT};
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
