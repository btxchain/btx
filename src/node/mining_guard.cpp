// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mining_guard.h>

#include <common/args.h>
#include <net.h>
#include <net_processing.h>
#include <node/context.h>
#include <sync.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <vector>

namespace node {
namespace {
int ComputeMedianTip(std::vector<int> peer_heights)
{
    if (peer_heights.empty()) return -1;

    std::sort(peer_heights.begin(), peer_heights.end());
    const size_t middle = peer_heights.size() / 2;
    if ((peer_heights.size() & 1U) != 0U) {
        return peer_heights[middle];
    }
    return (peer_heights[middle - 1] + peer_heights[middle]) / 2;
}
} // namespace

MiningChainGuardOptions GetMiningChainGuardOptions(const NodeContext& node)
{
    MiningChainGuardOptions options;

    const bool default_enabled =
        node.chainman != nullptr && !node.chainman->GetParams().IsTestChain();

    if (!node.args) {
        options.enabled = default_enabled;
        return options;
    }

    options.explicit_setting =
        node.args->IsArgSet("-miningchainguard") || node.args->IsArgNegated("-miningchainguard");
    options.enabled = node.args->GetBoolArg("-miningchainguard", default_enabled);
    options.min_peer_count = std::max<int>(
        1,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardminpeers", DEFAULT_MINING_CHAIN_GUARD_MIN_PEERS)));
    options.max_median_tip_gap = std::max<int>(
        1,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardmaxmediangap", DEFAULT_MINING_CHAIN_GUARD_MAX_MEDIAN_GAP)));
    return options;
}

MiningChainGuardStatus EvaluateMiningChainGuard(
    int local_tip_height,
    bool initial_block_download,
    bool network_active,
    const std::vector<int>& peer_heights,
    const MiningChainGuardOptions& options)
{
    MiningChainGuardStatus status;
    status.enabled = options.enabled;
    status.initial_block_download = initial_block_download;
    status.network_active = network_active;
    status.local_tip_height = local_tip_height;
    status.peer_count = static_cast<int>(peer_heights.size());
    status.min_peer_count = options.min_peer_count;
    status.max_median_tip_gap = options.max_median_tip_gap;

    if (!options.enabled) {
        status.reason = "disabled";
        return status;
    }

    status.healthy = false;

    if (local_tip_height < 0) {
        status.reason = "tip_uninitialized";
        return status;
    }

    if (initial_block_download) {
        status.reason = "initial_block_download";
        return status;
    }

    if (!network_active) {
        status.reason = "network_inactive";
        return status;
    }

    if (status.peer_count < options.min_peer_count) {
        status.reason = "insufficient_peer_consensus";
        return status;
    }

    status.best_peer_tip = *std::max_element(peer_heights.begin(), peer_heights.end());
    status.worst_peer_tip = *std::min_element(peer_heights.begin(), peer_heights.end());
    status.median_peer_tip = ComputeMedianTip(peer_heights);
    status.near_tip_peers = std::count_if(
        peer_heights.begin(), peer_heights.end(), [&](int peer_height) {
            return std::abs(peer_height - local_tip_height) <= options.near_tip_window;
        });

    if (status.median_peer_tip < local_tip_height - options.max_median_tip_gap) {
        status.reason = "local_tip_ahead_of_peer_median";
        return status;
    }

    if (status.median_peer_tip > local_tip_height + options.max_median_tip_gap) {
        status.reason = "local_tip_behind_peer_median";
        return status;
    }

    status.healthy = true;
    status.reason = "healthy";
    return status;
}

std::vector<int> FilterMiningChainGuardPeerHeights(
    int local_tip_height,
    int64_t now,
    const std::vector<MiningChainGuardPeerSample>& peers,
    const MiningChainGuardOptions& options)
{
    std::vector<int> heights;
    heights.reserve(peers.size());
    for (const auto& peer : peers) {
        if (peer.height >= 0) heights.push_back(peer.height);
    }
    if (heights.empty()) return heights;

    const int best_peer_tip = *std::max_element(heights.begin(), heights.end());
    const int competitive_floor = best_peer_tip - options.max_median_tip_gap;

    std::vector<int> filtered;
    filtered.reserve(heights.size());
    for (const auto& peer : peers) {
        if (peer.height < 0) continue;

        // Keep peers close enough to the best observed tip so the guard still
        // reacts immediately to a live minority-fork risk.
        if (peer.height >= competitive_floor) {
            filtered.push_back(peer.height);
            continue;
        }

        // Peers outside that competitive band only count if they have seen or
        // announced a block recently enough to still look like live network
        // consensus instead of a stale lagging connection.
        const int64_t freshest_signal = std::max(peer.last_block_time, peer.last_block_announcement);
        if (freshest_signal > 0 && now - freshest_signal <= options.stale_peer_seconds) {
            filtered.push_back(peer.height);
        }
    }

    return filtered;
}

MiningChainGuardStatus GetMiningChainGuardStatus(const NodeContext& node)
{
    const MiningChainGuardOptions options = GetMiningChainGuardOptions(node);

    const bool network_active = node.connman && node.connman->GetNetworkActive();
    const int local_tip_height =
        node.chainman ? WITH_LOCK(cs_main, return node.chainman->ActiveChain().Height()) : -1;
    const bool initial_block_download =
        node.chainman ? node.chainman->IsInitialBlockDownload() : false;

    if (!options.enabled) {
        return EvaluateMiningChainGuard(
            local_tip_height, initial_block_download, network_active, {}, options);
    }

    if (!node.connman || !node.peerman || !node.chainman) {
        if (!options.explicit_setting) {
            MiningChainGuardOptions disabled_options = options;
            disabled_options.enabled = false;
            return EvaluateMiningChainGuard(
                local_tip_height, initial_block_download, network_active, {}, disabled_options);
        }
        MiningChainGuardStatus status = EvaluateMiningChainGuard(
            local_tip_height, initial_block_download, network_active, {}, options);
        status.reason = "peer_monitor_unavailable";
        return status;
    }

    std::vector<CNodeStats> node_stats;
    node.connman->GetNodeStats(node_stats);

    std::vector<MiningChainGuardPeerSample> peer_samples;
    peer_samples.reserve(node_stats.size());

    for (const CNodeStats& peer_stats : node_stats) {
        // Guard against local mining on minority forks using the node's own
        // outbound view of the network rather than potentially spoofed inbound peers.
        if (peer_stats.fInbound) continue;

        CNodeStateStats state_stats;
        if (!node.peerman->GetNodeStateStats(peer_stats.nodeid, state_stats)) continue;

        const int peer_height =
            state_stats.nSyncHeight >= 0 ? state_stats.nSyncHeight : state_stats.nCommonHeight;
        if (peer_height >= 0) {
            MiningChainGuardPeerSample sample;
            sample.height = peer_height;
            sample.last_block_time = peer_stats.m_last_block_time.count();
            sample.last_block_announcement =
                TicksSinceEpoch<std::chrono::seconds>(state_stats.m_last_block_announcement);
            peer_samples.push_back(sample);
        }
    }

    const int64_t now = GetTime<std::chrono::seconds>().count();
    const auto peer_heights =
        FilterMiningChainGuardPeerHeights(local_tip_height, now, peer_samples, options);

    return EvaluateMiningChainGuard(
        local_tip_height, initial_block_download, network_active, peer_heights, options);
}

std::string DescribeMiningChainGuardStatus(const MiningChainGuardStatus& status)
{
    std::ostringstream description;
    description << status.reason
                << " local_tip=" << status.local_tip_height
                << " peers=" << status.peer_count;

    if (status.peer_count > 0) {
        description << " median_peer_tip=" << status.median_peer_tip
                    << " best_peer_tip=" << status.best_peer_tip
                    << " near_tip_peers=" << status.near_tip_peers;
    }

    description << " min_peers=" << status.min_peer_count
                << " max_median_gap=" << status.max_median_tip_gap;
    return description.str();
}

bool ShouldPauseMiningByChainGuard(const MiningChainGuardStatus& status)
{
    return status.enabled && !status.healthy;
}

const char* GetMiningChainGuardRecommendedAction(const MiningChainGuardStatus& status)
{
    if (!ShouldPauseMiningByChainGuard(status)) return "continue";

    if (status.reason == "initial_block_download" ||
        status.reason == "local_tip_ahead_of_peer_median" ||
        status.reason == "local_tip_behind_peer_median") {
        return "catch_up";
    }

    return "pause";
}
} // namespace node
