// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINING_GUARD_H
#define BITCOIN_NODE_MINING_GUARD_H

#include <cstdint>
#include <string>
#include <vector>

namespace node {
struct NodeContext;

static constexpr int DEFAULT_MINING_CHAIN_GUARD_MIN_PEERS{3};
static constexpr int DEFAULT_MINING_CHAIN_GUARD_MIN_NEAR_TIP_PEERS{2};
static constexpr int DEFAULT_MINING_CHAIN_GUARD_MAX_MEDIAN_GAP{2};
static constexpr int DEFAULT_MINING_CHAIN_GUARD_NEAR_TIP_WINDOW{2};
static constexpr int DEFAULT_MINING_CHAIN_GUARD_STALE_PEER_SECONDS{120};
static constexpr int DEFAULT_MINING_CHAIN_GUARD_DEFERRED_REORG_WATCH_SECONDS{900};
static constexpr int DEFAULT_MINING_CHAIN_GUARD_MESH_REFRESH_SECONDS{60};

struct MiningChainGuardOptions {
    bool enabled{false};
    bool explicit_setting{false};
    bool refresh_default_mesh{true};
    int min_peer_count{DEFAULT_MINING_CHAIN_GUARD_MIN_PEERS};
    int min_near_tip_peers{DEFAULT_MINING_CHAIN_GUARD_MIN_NEAR_TIP_PEERS};
    int max_median_tip_gap{DEFAULT_MINING_CHAIN_GUARD_MAX_MEDIAN_GAP};
    int near_tip_window{DEFAULT_MINING_CHAIN_GUARD_NEAR_TIP_WINDOW};
    int stale_peer_seconds{DEFAULT_MINING_CHAIN_GUARD_STALE_PEER_SECONDS};
    int deferred_reorg_watch_seconds{DEFAULT_MINING_CHAIN_GUARD_DEFERRED_REORG_WATCH_SECONDS};
    int mesh_refresh_seconds{DEFAULT_MINING_CHAIN_GUARD_MESH_REFRESH_SECONDS};
};

struct MiningChainGuardPeerSample {
    int height{-1};
    int64_t last_block_time{0};
    int64_t last_block_announcement{0};
};

struct MiningChainGuardStatus {
    bool enabled{false};
    bool healthy{true};
    bool initial_block_download{false};
    bool network_active{true};
    int local_tip_height{-1};
    int peer_count{0};
    int median_peer_tip{-1};
    int best_peer_tip{-1};
    int worst_peer_tip{-1};
    int near_tip_peers{0};
    int min_peer_count{DEFAULT_MINING_CHAIN_GUARD_MIN_PEERS};
    int min_near_tip_peers{DEFAULT_MINING_CHAIN_GUARD_MIN_NEAR_TIP_PEERS};
    int max_median_tip_gap{DEFAULT_MINING_CHAIN_GUARD_MAX_MEDIAN_GAP};
    int near_tip_window{DEFAULT_MINING_CHAIN_GUARD_NEAR_TIP_WINDOW};
    int deferred_reorg_watch_seconds{DEFAULT_MINING_CHAIN_GUARD_DEFERRED_REORG_WATCH_SECONDS};
    uint32_t last_deferred_reorg_depth{0};
    uint32_t last_deferred_required_work_margin{0};
    int32_t last_deferred_tip_height{0};
    int32_t last_deferred_fork_height{0};
    int32_t last_deferred_candidate_height{0};
    int64_t last_deferred_unix{0};
    std::string reason{"disabled"};
};

const std::vector<std::string>& DefaultMiningPeerMesh();

MiningChainGuardOptions GetMiningChainGuardOptions(const NodeContext& node);

MiningChainGuardStatus EvaluateMiningChainGuard(
    int local_tip_height,
    bool initial_block_download,
    bool network_active,
    const std::vector<int>& peer_heights,
    const MiningChainGuardOptions& options);

std::vector<int> FilterMiningChainGuardPeerHeights(
    int local_tip_height,
    int64_t now,
    const std::vector<MiningChainGuardPeerSample>& peers,
    const MiningChainGuardOptions& options);

MiningChainGuardStatus GetMiningChainGuardStatus(const NodeContext& node);

std::string DescribeMiningChainGuardStatus(const MiningChainGuardStatus& status);
void MaybeRequestMiningChainGuardRecovery(const MiningChainGuardStatus& status, const NodeContext& node);
bool ShouldPauseMiningByChainGuard(const MiningChainGuardStatus& status);
const char* GetMiningChainGuardRecommendedAction(const MiningChainGuardStatus& status);
} // namespace node

#endif // BITCOIN_NODE_MINING_GUARD_H
