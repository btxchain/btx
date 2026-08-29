// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mining_guard.h>

#include <common/args.h>
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <node/context.h>
#include <sync.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace node {
namespace {
std::atomic<int64_t> g_last_default_mesh_refresh{0};
std::atomic<int64_t> g_last_guard_recovery_escalation{0};

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

const std::vector<std::string>& DefaultMiningPeerMesh()
{
    static const std::vector<std::string> default_mesh{
        "node.btx.dev:19335",
        "node.btxchain.org:19335",
        "node.btx.tools:19335",
    };
    return default_mesh;
}

void ResetMiningChainGuardMeshRefreshForTest()
{
    g_last_default_mesh_refresh.store(0);
}

void ResetMiningChainGuardRecoveryEscalationForTest()
{
    g_last_guard_recovery_escalation.store(0);
}

MiningChainGuardOptions GetMiningChainGuardOptions(const NodeContext& node)
{
    MiningChainGuardOptions options;

    const bool default_enabled =
        node.chainman != nullptr && !node.chainman->GetParams().IsTestChain();

    if (!node.args) {
        options.enabled = default_enabled;
        options.peer_mesh = DefaultMiningPeerMesh();
        return options;
    }

    options.explicit_setting =
        node.args->IsArgSet("-miningchainguard") || node.args->IsArgNegated("-miningchainguard");
    options.enabled = node.args->GetBoolArg("-miningchainguard", default_enabled);
    options.refresh_default_mesh = node.args->GetBoolArg("-miningchainguarddefaultmesh", true);
    if (node.args->IsArgNegated("-miningpeermesh")) {
        options.peer_mesh.clear();
    } else if (node.args->IsArgSet("-miningpeermesh")) {
        // Replace, do not append: operators must be able to opt out of the
        // compiled operator domains.
        options.peer_mesh = node.args->GetArgs("-miningpeermesh");
    } else {
        options.peer_mesh = DefaultMiningPeerMesh();
    }
    options.min_peer_count = std::max<int>(
        1,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardminpeers", DEFAULT_MINING_CHAIN_GUARD_MIN_PEERS)));
    options.min_near_tip_peers = std::max<int>(
        1,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardminneartippeers", DEFAULT_MINING_CHAIN_GUARD_MIN_NEAR_TIP_PEERS)));
    options.max_median_tip_gap = std::max<int>(
        1,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardmaxmediangap", DEFAULT_MINING_CHAIN_GUARD_MAX_MEDIAN_GAP)));
    options.near_tip_window = std::max<int>(
        0,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardneartipwindow", DEFAULT_MINING_CHAIN_GUARD_NEAR_TIP_WINDOW)));
    options.stale_peer_seconds = std::max<int>(
        1,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardstalepeerseconds", DEFAULT_MINING_CHAIN_GUARD_STALE_PEER_SECONDS)));
    options.deferred_reorg_watch_seconds = std::max<int>(
        0,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguarddeferredreorgwatchseconds",
            DEFAULT_MINING_CHAIN_GUARD_DEFERRED_REORG_WATCH_SECONDS)));
    options.mesh_refresh_seconds = std::max<int>(
        0,
        static_cast<int>(node.args->GetIntArg(
            "-miningchainguardmeshrefreshseconds",
            DEFAULT_MINING_CHAIN_GUARD_MESH_REFRESH_SECONDS)));
    return options;
}

static MiningChainGuardStatus ApplyDeferredReorgWarning(
    MiningChainGuardStatus status,
    const MiningChainGuardOptions& options,
    int64_t now)
{
    status.deferred_reorg_watch_seconds = options.deferred_reorg_watch_seconds;

    const auto stats = ProbeReorgProtectionRuntimeStats();
    status.last_deferred_reorg_depth = stats.last_deferred_reorg_depth;
    status.last_deferred_required_work_margin = stats.last_deferred_required_work_margin;
    status.last_deferred_tip_height = stats.last_deferred_tip_height;
    status.last_deferred_fork_height = stats.last_deferred_fork_height;
    status.last_deferred_candidate_height = stats.last_deferred_candidate_height;
    status.last_deferred_unix = stats.last_deferred_unix;

    if (!status.enabled || !status.healthy || options.deferred_reorg_watch_seconds <= 0) {
        return status;
    }

    if (stats.last_deferred_unix <= 0) return status;

    const int64_t latest_resolution = std::max(stats.last_observed_unix, stats.last_rejected_unix);
    if (stats.last_deferred_unix <= latest_resolution) return status;

    const int64_t deferred_age = now - stats.last_deferred_unix;
    if (deferred_age < 0 || deferred_age > options.deferred_reorg_watch_seconds) {
        return status;
    }

    status.healthy = false;
    status.reason = "deferred_reorg_candidate";
    return status;
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
    status.min_near_tip_peers = options.min_near_tip_peers;
    status.max_median_tip_gap = options.max_median_tip_gap;
    status.near_tip_window = options.near_tip_window;
    status.stale_peer_seconds = options.stale_peer_seconds;
    status.refresh_default_mesh = options.refresh_default_mesh;
    status.mesh_refresh_seconds = options.mesh_refresh_seconds;
    status.deferred_reorg_watch_seconds = options.deferred_reorg_watch_seconds;

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

    if (status.peer_count > 0) {
        status.best_peer_tip = *std::max_element(peer_heights.begin(), peer_heights.end());
        status.worst_peer_tip = *std::min_element(peer_heights.begin(), peer_heights.end());
        status.median_peer_tip = ComputeMedianTip(peer_heights);
        status.near_tip_peers = std::count_if(
            peer_heights.begin(), peer_heights.end(), [&](int peer_height) {
                return std::abs(peer_height - local_tip_height) <= options.near_tip_window;
            });

        // Catch-up is not isolation. A node with even one peer clearly
        // above its tip must report local_tip_behind, not
        // insufficient_peer_consensus. The old order required
        // min_peer_count known BestKnown hashes first, so headers-level
        // visibility of 23 peers ahead still looked like an empty mesh
        // (a live consensus-archive node / PR 126).
        if (status.median_peer_tip > local_tip_height + options.max_median_tip_gap) {
            status.reason = "local_tip_behind_peer_median";
            return status;
        }

        if (status.median_peer_tip < local_tip_height - options.max_median_tip_gap) {
            status.reason = "local_tip_ahead_of_peer_median";
            return status;
        }
    }

    if (status.peer_count < options.min_peer_count) {
        status.reason = "insufficient_peer_consensus";
        return status;
    }

    if (status.near_tip_peers < options.min_near_tip_peers) {
        status.reason = "insufficient_near_tip_peers";
        return status;
    }

    status.healthy = true;
    status.reason = "healthy";
    return status;
}

void ApplyPeerTipHashCheck(
    MiningChainGuardStatus& status,
    int local_tip_height,
    const std::string& local_tip_hash,
    const std::vector<MiningChainGuardPeerSample>& peers)
{
    status.local_tip_hash = local_tip_hash;
    status.same_tip_hash_peers = 0;
    status.conflicting_tip_hash_peers = 0;

    if (status.initial_block_download || local_tip_hash.empty() ||
        local_tip_height < 0) {
        status.island_suspect =
            status.reason == "insufficient_peer_consensus" ||
            status.reason == "insufficient_near_tip_peers";
        return;
    }

    // Catch-up: peers sit above our tip, so same-height hash agreement
    // cannot be observed. That is not mining-alone.
    if (status.reason == "local_tip_behind_peer_median") {
        status.island_suspect = false;
        return;
    }

    for (const auto& peer : peers) {
        if (peer.hash.empty() || peer.height != local_tip_height) continue;
        if (peer.hash == local_tip_hash) {
            ++status.same_tip_hash_peers;
        } else {
            ++status.conflicting_tip_hash_peers;
        }
    }

    const bool isolated =
        status.reason == "insufficient_peer_consensus" ||
        status.reason == "insufficient_near_tip_peers";
    const bool hash_split = status.conflicting_tip_hash_peers > 0 &&
                            status.same_tip_hash_peers < status.min_near_tip_peers;
    status.island_suspect = isolated || hash_split;
    if (!hash_split || !status.healthy) return;
    status.healthy = false;
    status.reason = "peer_tip_hash_mismatch";
    LogPrintLevel(
        BCLog::NET,
        BCLog::Level::Warning,
        "Mining chain guard island_suspect reason=%s same_tip_hash_peers=%d conflicting_tip_hash_peers=%d local_tip=%d\n",
        status.reason,
        status.same_tip_hash_peers,
        status.conflicting_tip_hash_peers,
        local_tip_height);
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

std::vector<MiningChainGuardPeerSample> FilterMiningChainGuardConsensusSamples(
    const std::vector<MiningChainGuardPeerSample>& peers)
{
    std::vector<MiningChainGuardPeerSample> consensus;
    consensus.reserve(peers.size());
    for (const auto& peer : peers) {
        if (peer.outbound && !peer.hash.empty()) {
            consensus.push_back(peer);
        }
    }
    return consensus;
}

MiningChainGuardStatus RefineMiningChainGuardConsensus(
    const MiningChainGuardStatus& visibility,
    int local_tip_height,
    bool initial_block_download,
    bool network_active,
    const std::vector<int>& consensus_heights,
    const MiningChainGuardOptions& options)
{
    if (visibility.reason != "healthy" &&
        visibility.reason != "insufficient_peer_consensus" &&
        visibility.reason != "insufficient_near_tip_peers") {
        return visibility;
    }
    return EvaluateMiningChainGuard(
        local_tip_height, initial_block_download, network_active, consensus_heights, options);
}

namespace {
bool MiningChainGuardKnownHashOnActiveOrBestChain(
    const ChainstateManager& chainman,
    const std::string& hash_hex)
{
    AssertLockHeld(::cs_main);
    const auto parsed = uint256::FromHex(hash_hex);
    if (!parsed) return false;
    const CBlockIndex* index = chainman.m_blockman.LookupBlockIndex(*parsed);
    if (index == nullptr) return false;
    const CBlockIndex* tip = chainman.ActiveChain().Tip();
    if (tip != nullptr && tip->GetAncestor(index->nHeight) == index) return true;
    const CBlockIndex* best = chainman.m_best_header;
    if (best != nullptr && best->GetAncestor(index->nHeight) == index) return true;
    return false;
}

std::vector<MiningChainGuardPeerSample> FilterMiningChainGuardOnChainConsensusSamples(
    const ChainstateManager& chainman,
    const std::vector<MiningChainGuardPeerSample>& peers)
{
    AssertLockHeld(::cs_main);
    std::vector<MiningChainGuardPeerSample> on_chain;
    on_chain.reserve(peers.size());
    for (const auto& peer : peers) {
        if (MiningChainGuardKnownHashOnActiveOrBestChain(chainman, peer.hash)) {
            on_chain.push_back(peer);
        }
    }
    return on_chain;
}
} // namespace

MiningChainGuardStatus GetMiningChainGuardStatus(const NodeContext& node)
{
    const MiningChainGuardOptions options = GetMiningChainGuardOptions(node);

    const bool network_active = node.connman && node.connman->GetNetworkActive();
    int local_tip_height{-1};
    std::string local_tip_hash;
    if (node.chainman) {
        LOCK(cs_main);
        const CBlockIndex* const tip{node.chainman->ActiveChain().Tip()};
        if (tip != nullptr) {
            local_tip_height = tip->nHeight;
            local_tip_hash = tip->GetBlockHash().GetHex();
        }
    }
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
        CNodeStateStats state_stats;
        if (!node.peerman->GetNodeStateStats(peer_stats.nodeid, state_stats)) continue;

        const int peer_height =
            state_stats.nSyncHeight >= 0
                ? state_stats.nSyncHeight
                : (state_stats.nCommonHeight >= 0
                       ? state_stats.nCommonHeight
                       : state_stats.m_starting_height);
        if (peer_height < 0) continue;

        // Isolation / hash-split uses the outbound view. Catch-up also
        // counts inbound peers that advertise above the local tip:
        // VERSION height is headers-level visibility, and requiring a
        // BestKnown hash first is how a far-behind archive reported
        // insufficient_peer_consensus with 23 peers ahead.
        if (peer_stats.fInbound && peer_height <= local_tip_height) continue;

        MiningChainGuardPeerSample sample;
        sample.height = peer_height;
        sample.outbound = !peer_stats.fInbound;
        sample.hash = peer_stats.fInbound ? std::string{} : state_stats.m_best_known_block_hash;
        sample.last_block_time = peer_stats.m_last_block_time.count();
        sample.last_block_announcement =
            TicksSinceEpoch<std::chrono::seconds>(state_stats.m_last_block_announcement);
        peer_samples.push_back(sample);
    }

    const int64_t now = GetTime<std::chrono::seconds>().count();
    const auto visibility_heights =
        FilterMiningChainGuardPeerHeights(local_tip_height, now, peer_samples, options);

    auto status = EvaluateMiningChainGuard(
        local_tip_height, initial_block_download, network_active, visibility_heights, options);

    const auto consensus_samples = FilterMiningChainGuardConsensusSamples(peer_samples);
    std::vector<MiningChainGuardPeerSample> on_chain_samples;
    {
        LOCK(cs_main);
        on_chain_samples =
            FilterMiningChainGuardOnChainConsensusSamples(*node.chainman, consensus_samples);
    }
    const auto consensus_heights =
        FilterMiningChainGuardPeerHeights(local_tip_height, now, on_chain_samples, options);
    status = RefineMiningChainGuardConsensus(
        status,
        local_tip_height,
        initial_block_download,
        network_active,
        consensus_heights,
        options);
    // Hash-split still sees every learned outbound hash, including competing
    // forks that the on-chain count correctly excluded.
    ApplyPeerTipHashCheck(status, local_tip_height, local_tip_hash, consensus_samples);
    return ApplyDeferredReorgWarning(std::move(status), options, now);
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
                << " min_near_tip_peers=" << status.min_near_tip_peers
                << " near_tip_window=" << status.near_tip_window
                << " max_median_gap=" << status.max_median_tip_gap;
    if (status.last_deferred_unix > 0) {
        description << " last_deferred_reorg_depth=" << status.last_deferred_reorg_depth
                    << " last_deferred_candidate_height=" << status.last_deferred_candidate_height
                    << " deferred_reorg_watch_seconds=" << status.deferred_reorg_watch_seconds;
    }
    return description.str();
}

void MaybeRequestMiningChainGuardRecovery(const MiningChainGuardStatus& status, const NodeContext& node)
{
    if (!status.enabled || status.healthy || !node.connman) return;

    const MiningChainGuardOptions options = GetMiningChainGuardOptions(node);

    if (status.reason == "tip_uninitialized" ||
        status.reason == "initial_block_download" ||
        status.reason == "network_inactive" ||
        status.reason == "local_tip_behind_peer_median" ||
        status.reason == "local_tip_ahead_of_peer_median" ||
        status.reason == "insufficient_peer_consensus" ||
        status.reason == "insufficient_near_tip_peers" ||
        status.reason == "peer_tip_hash_mismatch" ||
        status.reason == "deferred_reorg_candidate" ||
        status.reason == "peer_monitor_unavailable") {
        const int64_t now = GetTime<std::chrono::seconds>().count();
        const int escalation_interval = std::max(
            options.mesh_refresh_seconds, DEFAULT_MINING_CHAIN_GUARD_MESH_REFRESH_SECONDS);
        int64_t last_escalation = g_last_guard_recovery_escalation.load();
        while (MiningChainGuardRecoveryEscalationDue(now, last_escalation, escalation_interval) &&
               !g_last_guard_recovery_escalation.compare_exchange_weak(last_escalation, now)) {
        }
        if (MiningChainGuardRecoveryEscalationDue(now, last_escalation, escalation_interval)) {
            node.connman->SetTryNewOutboundPeer(true);
            node.connman->StartExtraBlockRelayPeers();
        }

        if (options.refresh_default_mesh &&
            options.mesh_refresh_seconds > 0 &&
            status.network_active) {
            int64_t last = g_last_default_mesh_refresh.load();
            while (now - last >= options.mesh_refresh_seconds &&
                   !g_last_default_mesh_refresh.compare_exchange_weak(last, now)) {
            }
            if (now - last >= options.mesh_refresh_seconds) {
                const bool use_v2transport = node.connman->GetLocalServices() & NODE_P2P_V2;
                int added{0};
                for (const auto& peer : options.peer_mesh) {
                    if (node.connman->AddNode({peer, use_v2transport})) {
                        ++added;
                    }
                }
                LogPrintLevel(
                    BCLog::NET,
                    BCLog::Level::Info,
                    "Mining chain guard refreshed configured peer mesh (%u peers, %d newly added) after %s\n",
                    static_cast<unsigned>(options.peer_mesh.size()),
                    added,
                    DescribeMiningChainGuardStatus(status));
            }
        }
    }
}

bool ShouldPauseMiningByChainGuard(const MiningChainGuardStatus& status)
{
    (void)status;
    return false;
}

const char* GetMiningChainGuardRecommendedAction(const MiningChainGuardStatus& status)
{
    if (status.reason == "tip_uninitialized") {
        return "wait_for_tip";
    }

    if (status.reason == "initial_block_download" ||
        status.reason == "local_tip_behind_peer_median") {
        return "mine_current_tip_and_catch_up";
    }

    if (status.reason == "network_inactive") {
        return "mine_current_tip_and_enable_network";
    }

    if (status.reason == "deferred_reorg_candidate") {
        return "mine_current_tip";
    }

    if (status.reason == "local_tip_ahead_of_peer_median") {
        return "propagate_tip";
    }

    if (status.reason == "peer_tip_hash_mismatch") {
        return "check_attested_tip";
    }

    if (status.reason == "insufficient_peer_consensus" ||
        status.reason == "insufficient_near_tip_peers" ||
        status.reason == "peer_monitor_unavailable") {
        return "add_outbound_peers";
    }

    if (!status.healthy) {
        return "continue_with_warning";
    }

    return "continue";
}
} // namespace node
