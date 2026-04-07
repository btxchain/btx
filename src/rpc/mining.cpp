// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <hash.h>
#include <interfaces/mining.h>
#include <key_io.h>
#include <logging.h>
#include <matmul/accelerated_solver.h>
#include <matmul/field.h>
#include <matmul/matmul_pow.h>
#include <net.h>
#include <net_processing.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/mining_guard.h>
#include <node/warnings.h>
#include <policy/ephemeral_policy.h>
#include <pow.h>
#include <pqkey.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/syserror.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <atomic>
#include <chrono>
#include <charconv>
#include <cstdlib>
#include <memory>
#include <stdint.h>
#include <cmath>
#include <limits>
#include <map>
#include <numeric>
#include <thread>
#include <algorithm>
#include <array>
#include <vector>

using interfaces::BlockRef;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;
using node::GetMinimumTime;
using node::NodeContext;
using node::RegenerateCommitments;
using node::UpdateTime;
using util::ToString;

static int64_t DefaultMinOutboundPeersForMiningTemplate(const CChainParams& params)
{
    return params.GetChainType() == ChainType::MAIN ? 2 : 0;
}

static int64_t DefaultMaxHeaderLagForMiningTemplate(const CChainParams& params)
{
    // Allow small transient lag, but avoid mining from a significantly stale
    // validated tip when better headers are already known.
    return params.GetChainType() == ChainType::MAIN ? 8 : 0;
}

static int64_t DefaultMinSyncedOutboundPeersForMiningTemplate(const CChainParams& params)
{
    return params.GetChainType() == ChainType::MAIN ? 1 : 0;
}

static int64_t DefaultMaxPeerSyncHeightLagForMiningTemplate(const CChainParams& params)
{
    return params.GetChainType() == ChainType::MAIN ? 2 : 0;
}

struct OutboundPeerDiagnostic
{
    std::string addr;
    std::string connection_type;
    bool manual{false};
    int sync_height{-1};
    int common_height{-1};
    int presync_height{-1};
    int starting_height{-1};
    int sync_lag{-1};
    int64_t last_block_time{0};
    int64_t last_block_announcement{0};
    bool counts_as_synced_outbound{false};
};

struct OutboundPeerDiagnosticsSummary
{
    size_t synced_outbound_peers{0};
    size_t manual_outbound_peers{0};
    size_t outbound_peers_missing_sync_height{0};
    size_t outbound_peers_beyond_sync_lag{0};
    size_t recent_block_announcing_outbound_peers{0};
    std::vector<OutboundPeerDiagnostic> peers;
};

static std::string OutboundPeerAddrLabel(const CNodeStats& stats)
{
    if (!stats.m_addr_name.empty()) return stats.m_addr_name;
    const std::string addr_port = stats.addr.ToStringAddrPort();
    if (!addr_port.empty()) return addr_port;
    return stats.addr.ToStringAddr();
}

static OutboundPeerDiagnosticsSummary CollectOutboundPeerDiagnostics(
    const CConnman& connman,
    const PeerManager* peerman,
    const int active_tip_height,
    const int64_t max_peer_sync_height_lag)
{
    OutboundPeerDiagnosticsSummary summary;
    std::vector<CNodeStats> vstats;
    connman.GetNodeStats(vstats);

    for (const CNodeStats& stats : vstats) {
        if (stats.fInbound) continue;

        OutboundPeerDiagnostic diag;
        diag.addr = OutboundPeerAddrLabel(stats);
        diag.connection_type = ConnectionTypeAsString(stats.m_conn_type);
        diag.manual = stats.m_conn_type == ConnectionType::MANUAL;
        diag.starting_height = stats.m_starting_height;
        diag.last_block_time = stats.m_last_block_time.count();

        if (diag.manual) {
            ++summary.manual_outbound_peers;
        }

        if (peerman != nullptr) {
            CNodeStateStats statestats;
            if (peerman->GetNodeStateStats(stats.nodeid, statestats)) {
                diag.sync_height = statestats.nSyncHeight;
                diag.common_height = statestats.nCommonHeight;
                diag.presync_height = statestats.presync_height;
                diag.last_block_announcement =
                    TicksSinceEpoch<std::chrono::seconds>(statestats.m_last_block_announcement);
            }
        }

        if (diag.last_block_announcement > 0) {
            ++summary.recent_block_announcing_outbound_peers;
        }

        if (diag.sync_height < 0) {
            ++summary.outbound_peers_missing_sync_height;
        } else {
            diag.sync_lag = std::max<int>(0, active_tip_height - diag.sync_height);
            diag.counts_as_synced_outbound = diag.sync_lag <= max_peer_sync_height_lag;
            if (diag.counts_as_synced_outbound) {
                ++summary.synced_outbound_peers;
            } else {
                ++summary.outbound_peers_beyond_sync_lag;
            }
        }

        summary.peers.push_back(std::move(diag));
    }

    return summary;
}

static size_t CountSyncedOutboundPeers(
    const CConnman& connman,
    const PeerManager& peerman,
    const int active_tip_height,
    const int64_t max_peer_sync_height_lag)
{
    return CollectOutboundPeerDiagnostics(
        connman,
        &peerman,
        active_tip_height,
        max_peer_sync_height_lag).synced_outbound_peers;
}

static void EnforceMiningTemplateReadiness(
    const ChainstateManager& chainman,
    const CConnman& connman,
    const PeerManager* peerman,
    Mining& miner,
    const bool enforce_connectivity,
    const int64_t min_outbound_peers,
    const int64_t min_synced_outbound_peers,
    const int64_t max_peer_sync_height_lag,
    const bool enforce_header_lag,
    const int64_t max_header_lag) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (enforce_connectivity) {
        if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, CLIENT_NAME " is not connected!");
        }

        if (min_outbound_peers > 0) {
            const size_t outbound_peers = connman.GetNodeCount(ConnectionDirection::Out);
            if (outbound_peers < static_cast<size_t>(min_outbound_peers)) {
                throw JSONRPCError(
                    RPC_CLIENT_NOT_CONNECTED,
                    strprintf("%s has %u outbound peers, requires at least %d for getblocktemplate; "
                              "set -miningminoutboundpeers=0 to disable",
                              CLIENT_NAME, outbound_peers, min_outbound_peers));
            }
        }

        if (miner.isInitialBlockDownload()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, CLIENT_NAME " is in initial sync and waiting for blocks...");
        }

        if (min_synced_outbound_peers > 0) {
            if (peerman == nullptr) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Peer manager unavailable while enforcing mining peer sync guard");
            }
            const CBlockIndex* const active_tip = chainman.ActiveChain().Tip();
            if (active_tip == nullptr) {
                throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, CLIENT_NAME " has no active tip yet");
            }

            const size_t synced_outbound_peers = CountSyncedOutboundPeers(
                connman,
                *peerman,
                active_tip->nHeight,
                max_peer_sync_height_lag);
            if (synced_outbound_peers < static_cast<size_t>(min_synced_outbound_peers)) {
                throw JSONRPCError(
                    RPC_CLIENT_NOT_CONNECTED,
                    strprintf(
                        "%s has %u synced outbound peers, requires at least %d within %d blocks of active tip for getblocktemplate; "
                        "set -miningminsyncedoutboundpeers=0 to disable",
                        CLIENT_NAME,
                        static_cast<unsigned>(synced_outbound_peers),
                        min_synced_outbound_peers,
                        static_cast<int>(max_peer_sync_height_lag)));
            }
        }
    }

    if (enforce_header_lag && max_header_lag > 0) {
        const CBlockIndex* const active_tip = chainman.ActiveChain().Tip();
        const CBlockIndex* const best_header = chainman.m_best_header;
        if (active_tip && best_header) {
            const int64_t header_lag = std::max<int64_t>(0, best_header->nHeight - active_tip->nHeight);
            if (header_lag > max_header_lag) {
                throw JSONRPCError(
                    RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                    strprintf(
                        "%s validated tip is %d blocks behind best header (%d > %d); "
                        "set -miningmaxheaderlag=0 to disable",
                        CLIENT_NAME,
                        header_lag,
                        header_lag,
                        max_header_lag));
            }
        }
    }
}

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is -1.
 * If 'height' is -1, compute the estimate from current chain tip.
 * If 'height' is a valid block height, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height, const CChain& active_chain) {
    if (lookup < -1 || lookup == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid nblocks. Must be a positive number or -1.");
    }

    if (height < -1 || height > active_chain.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block does not exist at specified height");
    }

    const CBlockIndex* pb = active_chain.Tip();

    if (height >= 0) {
        pb = active_chain[height];
    }

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup == -1)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    const CBlockIndex* pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

static bool TryGetNextBlockHeight(const CBlockIndex* pindex_prev, int& next_height)
{
    if (pindex_prev == nullptr) {
        next_height = 0;
        return true;
    }
    if (pindex_prev->nHeight == std::numeric_limits<int>::max()) return false;
    next_height = pindex_prev->nHeight + 1;
    return true;
}

struct IntervalHealthStats {
    size_t count{0};
    double mean_interval_s{0.0};
    double p50_interval_s{0.0};
    double p90_interval_s{0.0};
    double p99_interval_s{0.0};
    double stddev_interval_s{0.0};
    double mean_abs_error_s{0.0};
    double max_overshoot_s{0.0};
    double max_undershoot_s{0.0};
};

struct RewardRecipientStats {
    std::string recipient;
    int blocks{0};
    CAmount reward_sats{0};
};

struct RewardStreakStats {
    std::string recipient;
    int blocks{0};
    int start_height{0};
    int end_height{0};
    int start_index{-1};
    int end_index{-1};
    double recipient_share{0.0};
    double probability_at_least_observed{0.0};
    double probability_upper_bound{0.0};
    double log10_probability_upper_bound{0.0};
    bool statistically_improbable{false};
    int context_window_blocks{0};
    int context_start_height{0};
    int context_end_height{0};
    double context_recipient_share{0.0};
    int context_unique_recipients{0};
    double context_mean_interval_s{0.0};
    bool nonstationary_share_suspected{false};
};

struct RewardDistributionStats {
    size_t count{0};
    size_t unique_recipients{0};
    size_t unknown_recipients{0};
    double top_share{0.0};
    double top3_share{0.0};
    double hhi{0.0};
    double gini{0.0};
    CAmount total_reward_sats{0};
    RewardStreakStats longest_streak;
    std::vector<RewardRecipientStats> top_recipients;
};

static constexpr double REWARD_STREAK_IMPROBABLE_PROBABILITY{1e-6};

static RewardStreakStats ComputeRewardStreakSignificance(
    RewardStreakStats streak,
    const size_t total_blocks,
    const int recipient_blocks)
{
    if (total_blocks == 0 || recipient_blocks <= 0 || streak.blocks <= 0) {
        return streak;
    }

    const int bounded_streak = std::min<int>(streak.blocks, static_cast<int>(total_blocks));
    const double recipient_share = std::clamp(
        static_cast<double>(recipient_blocks) / static_cast<double>(total_blocks),
        0.0,
        1.0);
    double probability{0.0};
    double probability_upper_bound{0.0};

    if (recipient_share <= 0.0) {
        probability = 0.0;
        probability_upper_bound = 0.0;
    } else if (recipient_share >= 1.0) {
        probability = bounded_streak <= static_cast<int>(total_blocks) ? 1.0 : 0.0;
        probability_upper_bound = probability;
    } else {
        std::vector<double> dp(static_cast<size_t>(bounded_streak), 0.0);
        dp[0] = 1.0;
        for (size_t step = 0; step < total_blocks; ++step) {
            std::vector<double> next_dp(static_cast<size_t>(bounded_streak), 0.0);
            next_dp[0] = std::accumulate(dp.begin(), dp.end(), 0.0) * (1.0 - recipient_share);
            for (int run_length = 0; run_length < bounded_streak - 1; ++run_length) {
                next_dp[static_cast<size_t>(run_length + 1)] +=
                    dp[static_cast<size_t>(run_length)] * recipient_share;
            }
            probability += dp[static_cast<size_t>(bounded_streak - 1)] * recipient_share;
            dp = std::move(next_dp);
        }
        probability_upper_bound = std::min(
            1.0,
            std::max(
                0.0,
                static_cast<double>(total_blocks - static_cast<size_t>(bounded_streak) + 1) *
                    std::pow(recipient_share, bounded_streak)));
    }

    streak.recipient_share = recipient_share;
    streak.probability_at_least_observed = probability;
    streak.probability_upper_bound = probability_upper_bound;
    streak.log10_probability_upper_bound =
        probability_upper_bound <= 0.0 ? 0.0 : std::log10(probability_upper_bound);
    streak.statistically_improbable = probability <= REWARD_STREAK_IMPROBABLE_PROBABILITY;
    return streak;
}

struct RewardObservation {
    int height;
    int64_t time;
    std::string recipient;
    CAmount reward_sats;
};

static RewardStreakStats ComputeRewardStreakContext(
    RewardStreakStats streak,
    const std::vector<RewardObservation>& observations,
    const size_t total_blocks)
{
    if (observations.empty() || total_blocks == 0 || streak.blocks <= 0 ||
        streak.start_index < 0 || streak.end_index < streak.start_index) {
        return streak;
    }

    const int observation_count = static_cast<int>(observations.size());
    const int context_window_blocks = std::min<int>(
        observation_count,
        std::max(20, streak.blocks + 4));
    const int extra = std::max(0, context_window_blocks - streak.blocks);
    const int before = extra / 2;
    const int after = extra - before;

    int context_start_index = std::max(0, streak.start_index - before);
    int context_end_index = std::min(observation_count - 1, streak.end_index + after);
    int current_size = context_end_index - context_start_index + 1;
    if (current_size < context_window_blocks) {
        int missing = context_window_blocks - current_size;
        const int extend_left = std::min(missing, context_start_index);
        context_start_index -= extend_left;
        missing -= extend_left;
        context_end_index = std::min(observation_count - 1, context_end_index + missing);
    }

    std::map<std::string, int> context_grouped;
    int recipient_blocks = 0;
    double total_interval_s{0.0};
    int interval_count{0};
    for (int index = context_start_index; index <= context_end_index; ++index) {
        const auto& observation = observations[static_cast<size_t>(index)];
        ++context_grouped[observation.recipient];
        if (observation.recipient == streak.recipient) {
            ++recipient_blocks;
        }
        if (index > context_start_index) {
            const auto& previous = observations[static_cast<size_t>(index - 1)];
            total_interval_s += static_cast<double>(observation.time - previous.time);
            ++interval_count;
        }
    }

    const int actual_window = context_end_index - context_start_index + 1;
    streak.context_window_blocks = actual_window;
    streak.context_start_height = observations[static_cast<size_t>(context_start_index)].height;
    streak.context_end_height = observations[static_cast<size_t>(context_end_index)].height;
    streak.context_recipient_share = actual_window > 0
        ? static_cast<double>(recipient_blocks) / static_cast<double>(actual_window)
        : 0.0;
    streak.context_unique_recipients = static_cast<int>(context_grouped.size());
    streak.context_mean_interval_s = interval_count > 0
        ? total_interval_s / static_cast<double>(interval_count)
        : 0.0;
    streak.nonstationary_share_suspected =
        total_blocks >= 20 &&
        streak.blocks >= 10 &&
        streak.context_recipient_share >= 0.75 &&
        streak.context_recipient_share >= streak.recipient_share + 0.25;
    return streak;
}

static double Quantile(std::vector<double> values, double p)
{
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    const size_t idx = std::max<size_t>(0, std::min(values.size() - 1, static_cast<size_t>(std::ceil(p * values.size()) - 1)));
    return values[idx];
}

static IntervalHealthStats ComputeRecentIntervalStatsFromTip(
    const CBlockIndex* tip,
    int window_blocks,
    double target_spacing_s)
{
    IntervalHealthStats stats;
    if (window_blocks <= 0) return stats;

    std::vector<double> intervals;
    intervals.reserve(window_blocks);
    const CBlockIndex* cursor = tip;
    while (cursor != nullptr && cursor->pprev != nullptr && static_cast<int>(intervals.size()) < window_blocks) {
        intervals.push_back(static_cast<double>(cursor->GetBlockTime() - cursor->pprev->GetBlockTime()));
        cursor = cursor->pprev;
    }
    if (intervals.empty()) return stats;

    std::reverse(intervals.begin(), intervals.end());
    std::vector<double> abs_errors;
    abs_errors.reserve(intervals.size());
    double max_overshoot{0.0};
    double max_undershoot{0.0};
    for (const double interval_s : intervals) {
        abs_errors.push_back(std::abs(interval_s - target_spacing_s));
        max_overshoot = std::max(max_overshoot, std::max(0.0, interval_s - target_spacing_s));
        max_undershoot = std::max(max_undershoot, std::max(0.0, target_spacing_s - interval_s));
    }

    const double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / static_cast<double>(intervals.size());
    double variance{0.0};
    for (const double interval_s : intervals) {
        const double delta = interval_s - mean;
        variance += delta * delta;
    }
    variance /= static_cast<double>(intervals.size());

    const double mean_abs_error =
        std::accumulate(abs_errors.begin(), abs_errors.end(), 0.0) / static_cast<double>(abs_errors.size());

    stats.count = intervals.size();
    stats.mean_interval_s = mean;
    stats.p50_interval_s = Quantile(intervals, 0.50);
    stats.p90_interval_s = Quantile(intervals, 0.90);
    stats.p99_interval_s = Quantile(intervals, 0.99);
    stats.stddev_interval_s = std::sqrt(variance);
    stats.mean_abs_error_s = mean_abs_error;
    stats.max_overshoot_s = max_overshoot;
    stats.max_undershoot_s = max_undershoot;
    return stats;
}

static IntervalHealthStats ComputeRecentIntervalStats(
    const CChain& active_chain,
    int window_blocks,
    double target_spacing_s)
{
    return ComputeRecentIntervalStatsFromTip(active_chain.Tip(), window_blocks, target_spacing_s);
}

static UniValue IntervalStatsToUniValue(const IntervalHealthStats& stats)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("count", static_cast<uint64_t>(stats.count));
    obj.pushKV("mean_interval_s", stats.mean_interval_s);
    obj.pushKV("p50_interval_s", stats.p50_interval_s);
    obj.pushKV("p90_interval_s", stats.p90_interval_s);
    obj.pushKV("p99_interval_s", stats.p99_interval_s);
    obj.pushKV("stddev_interval_s", stats.stddev_interval_s);
    obj.pushKV("mean_abs_error_s", stats.mean_abs_error_s);
    obj.pushKV("max_overshoot_s", stats.max_overshoot_s);
    obj.pushKV("max_undershoot_s", stats.max_undershoot_s);
    return obj;
}

static std::string CoinbaseRecipientLabel(const CTxOut& txout)
{
    CTxDestination dest;
    if (ExtractDestination(txout.scriptPubKey, dest)) {
        return EncodeDestination(dest);
    }
    const std::string script_hex = HexStr(txout.scriptPubKey);
    if (!script_hex.empty()) {
        return strprintf("script:%s", script_hex);
    }
    return "unknown";
}

static RewardDistributionStats ComputeRecentRewardDistribution(
    ChainstateManager& chainman,
    const CChain& active_chain,
    int window_blocks)
{
    RewardDistributionStats stats;
    if (window_blocks <= 0) return stats;

    std::vector<RewardObservation> observations;
    observations.reserve(window_blocks);
    std::map<std::string, RewardRecipientStats> grouped;
    const CBlockIndex* cursor = active_chain.Tip();
    while (cursor != nullptr && static_cast<int>(stats.count) < window_blocks) {
        CBlock block;
        if (!chainman.m_blockman.ReadBlock(block, *cursor, /*lowprio=*/true)) {
            cursor = cursor->pprev;
            continue;
        }
        if (block.vtx.empty() || block.vtx[0]->vout.empty()) {
            cursor = cursor->pprev;
            continue;
        }

        const CTxOut& coinbase_output = block.vtx[0]->vout[0];
        const std::string recipient = CoinbaseRecipientLabel(coinbase_output);
        RewardRecipientStats& entry = grouped[recipient];
        entry.recipient = recipient;
        ++entry.blocks;
        entry.reward_sats += coinbase_output.nValue;
        observations.push_back({cursor->nHeight, cursor->GetBlockTime(), recipient, coinbase_output.nValue});
        ++stats.count;
        stats.total_reward_sats += coinbase_output.nValue;
        if (recipient == "unknown" || recipient.rfind("script:", 0) == 0) {
            ++stats.unknown_recipients;
        }
        cursor = cursor->pprev;
    }

    if (stats.count == 0) return stats;

    std::reverse(observations.begin(), observations.end());

    std::vector<RewardRecipientStats> entries;
    entries.reserve(grouped.size());
    for (const auto& [_, entry] : grouped) {
        entries.push_back(entry);
    }
    std::sort(entries.begin(), entries.end(), [](const RewardRecipientStats& lhs, const RewardRecipientStats& rhs) {
        if (lhs.blocks != rhs.blocks) return lhs.blocks > rhs.blocks;
        if (lhs.reward_sats != rhs.reward_sats) return lhs.reward_sats > rhs.reward_sats;
        return lhs.recipient < rhs.recipient;
    });

    stats.unique_recipients = entries.size();
    std::vector<double> shares;
    shares.reserve(entries.size());
    for (const RewardRecipientStats& entry : entries) {
        shares.push_back(static_cast<double>(entry.blocks) / static_cast<double>(stats.count));
    }

    stats.top_share = shares.empty() ? 0.0 : shares[0];
    stats.top3_share = std::accumulate(
        shares.begin(),
        shares.begin() + std::min<size_t>(3, shares.size()),
        0.0);
    stats.hhi = std::accumulate(shares.begin(), shares.end(), 0.0, [](double total, double share) {
        return total + (share * share);
    });

    if (!shares.empty()) {
        std::vector<double> sorted_shares{shares};
        std::sort(sorted_shares.begin(), sorted_shares.end());
        double weighted_sum{0.0};
        for (size_t index = 0; index < sorted_shares.size(); ++index) {
            weighted_sum += static_cast<double>(index + 1) * sorted_shares[index];
        }
        stats.gini =
            (2.0 * weighted_sum) /
                (static_cast<double>(sorted_shares.size()) *
                 std::accumulate(sorted_shares.begin(), sorted_shares.end(), 0.0)) -
            (static_cast<double>(sorted_shares.size()) + 1.0) / static_cast<double>(sorted_shares.size());
    }

    RewardStreakStats current_streak;
    for (size_t index = 0; index < observations.size(); ++index) {
        const RewardObservation& observation = observations[index];
        const bool extends_streak =
            current_streak.blocks > 0 &&
            current_streak.recipient == observation.recipient &&
            observation.height == current_streak.end_height + 1;
        if (extends_streak) {
            ++current_streak.blocks;
            current_streak.end_height = observation.height;
            current_streak.end_index = static_cast<int>(index);
        } else {
            current_streak = {
                .recipient = observation.recipient,
                .blocks = 1,
                .start_height = observation.height,
                .end_height = observation.height,
                .start_index = static_cast<int>(index),
                .end_index = static_cast<int>(index),
            };
        }
        if (current_streak.blocks > stats.longest_streak.blocks ||
            (current_streak.blocks == stats.longest_streak.blocks &&
             current_streak.start_height < stats.longest_streak.start_height)) {
            stats.longest_streak = current_streak;
        }
    }

    if (!stats.longest_streak.recipient.empty()) {
        const auto longest_entry = grouped.find(stats.longest_streak.recipient);
        if (longest_entry != grouped.end()) {
            stats.longest_streak = ComputeRewardStreakSignificance(
                stats.longest_streak,
                stats.count,
                longest_entry->second.blocks);
            stats.longest_streak = ComputeRewardStreakContext(
                stats.longest_streak,
                observations,
                stats.count);
        }
    }

    const size_t top_limit = std::min<size_t>(10, entries.size());
    stats.top_recipients.assign(entries.begin(), entries.begin() + top_limit);
    return stats;
}

static UniValue RewardDistributionToUniValue(const RewardDistributionStats& stats)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("count", static_cast<uint64_t>(stats.count));
    obj.pushKV("unique_recipients", static_cast<uint64_t>(stats.unique_recipients));
    obj.pushKV("unknown_recipients", static_cast<uint64_t>(stats.unknown_recipients));
    obj.pushKV("top_share", stats.top_share);
    obj.pushKV("top3_share", stats.top3_share);
    obj.pushKV("hhi", stats.hhi);
    obj.pushKV("gini", stats.gini);
    obj.pushKV("total_reward_sats", static_cast<int64_t>(stats.total_reward_sats));
    UniValue longest_streak(UniValue::VOBJ);
    longest_streak.pushKV("recipient", stats.longest_streak.recipient);
    longest_streak.pushKV("blocks", stats.longest_streak.blocks);
    longest_streak.pushKV("start_height", stats.longest_streak.start_height);
    longest_streak.pushKV("end_height", stats.longest_streak.end_height);
    longest_streak.pushKV(
        "block_share",
        stats.count == 0 ? 0.0 : static_cast<double>(stats.longest_streak.blocks) / static_cast<double>(stats.count));
    longest_streak.pushKV("recipient_share", stats.longest_streak.recipient_share);
    longest_streak.pushKV("probability_at_least_observed", stats.longest_streak.probability_at_least_observed);
    longest_streak.pushKV("probability_upper_bound", stats.longest_streak.probability_upper_bound);
    longest_streak.pushKV("log10_probability_upper_bound", stats.longest_streak.log10_probability_upper_bound);
    longest_streak.pushKV("statistically_improbable", stats.longest_streak.statistically_improbable);
    longest_streak.pushKV("context_window_blocks", stats.longest_streak.context_window_blocks);
    longest_streak.pushKV("context_start_height", stats.longest_streak.context_start_height);
    longest_streak.pushKV("context_end_height", stats.longest_streak.context_end_height);
    longest_streak.pushKV("context_recipient_share", stats.longest_streak.context_recipient_share);
    longest_streak.pushKV("context_unique_recipients", stats.longest_streak.context_unique_recipients);
    longest_streak.pushKV("context_mean_interval_s", stats.longest_streak.context_mean_interval_s);
    longest_streak.pushKV("nonstationary_share_suspected", stats.longest_streak.nonstationary_share_suspected);
    obj.pushKV("longest_streak", std::move(longest_streak));

    UniValue top_recipients(UniValue::VARR);
    for (const RewardRecipientStats& entry : stats.top_recipients) {
        UniValue recipient(UniValue::VOBJ);
        recipient.pushKV("recipient", entry.recipient);
        recipient.pushKV("blocks", entry.blocks);
        recipient.pushKV(
            "block_share",
            stats.count == 0 ? 0.0 : static_cast<double>(entry.blocks) / static_cast<double>(stats.count));
        recipient.pushKV("reward_sats", static_cast<int64_t>(entry.reward_sats));
        recipient.pushKV(
            "reward_share",
            stats.total_reward_sats == 0 ? 0.0 : static_cast<double>(entry.reward_sats) / static_cast<double>(stats.total_reward_sats));
        top_recipients.push_back(std::move(recipient));
    }
    obj.pushKV("top_recipients", std::move(top_recipients));
    return obj;
}

static UniValue RewardDistributionAlerts(const RewardDistributionStats& stats)
{
    UniValue alerts(UniValue::VARR);
    if (stats.count == 0) return alerts;
    if (stats.top_share > 0.45) {
        alerts.push_back(strprintf("reward top_share=%.4f above 0.45", stats.top_share));
    }
    if (stats.count >= 100 &&
        stats.longest_streak.blocks >= 20 &&
        static_cast<double>(stats.longest_streak.blocks) / static_cast<double>(stats.count) > 0.10) {
        alerts.push_back(
            strprintf("reward longest_streak=%d by %s above fairness threshold",
                      stats.longest_streak.blocks,
                      stats.longest_streak.recipient));
    }
    if (stats.count >= 100 && stats.longest_streak.statistically_improbable &&
        !stats.longest_streak.nonstationary_share_suspected) {
        alerts.push_back(
            strprintf("reward longest_streak=%d by %s is statistically improbable under stationary-share model (p=%.3e)",
                      stats.longest_streak.blocks,
                      stats.longest_streak.recipient,
                      stats.longest_streak.probability_at_least_observed));
    }
    if (stats.count >= 100 && stats.longest_streak.statistically_improbable &&
        stats.longest_streak.nonstationary_share_suspected) {
        alerts.push_back(
            strprintf("reward longest_streak=%d by %s reflects a locally dominant mining-share epoch (local_share=%.4f global_share=%.4f)",
                      stats.longest_streak.blocks,
                      stats.longest_streak.recipient,
                      stats.longest_streak.context_recipient_share,
                      stats.longest_streak.recipient_share));
    }
    if (stats.unknown_recipients > 0) {
        alerts.push_back(strprintf("reward unknown_recipients=%u", static_cast<unsigned int>(stats.unknown_recipients)));
    }
    return alerts;
}

static UniValue DifficultyAlerts(const IntervalHealthStats& stats)
{
    UniValue alerts(UniValue::VARR);
    if (stats.count == 0) return alerts;
    if (stats.mean_interval_s < 80.0) {
        alerts.push_back(strprintf("mean_interval_s=%.2f below target floor 80s", stats.mean_interval_s));
    }
    if (stats.mean_interval_s > 110.0) {
        alerts.push_back(strprintf("mean_interval_s=%.2f above target ceiling 110s", stats.mean_interval_s));
    }
    if (stats.p90_interval_s > 180.0) {
        alerts.push_back(strprintf("p90_interval_s=%.2f above 180s", stats.p90_interval_s));
    }
    if (stats.p99_interval_s > 420.0) {
        alerts.push_back(strprintf("p99_interval_s=%.2f above 420s", stats.p99_interval_s));
    }
    return alerts;
}

static int DifficultyHealthScore(const IntervalHealthStats& stats)
{
    if (stats.count == 0) return 0;
    double score{100.0};
    if (stats.mean_interval_s < 80.0) {
        score -= std::min(25.0, (80.0 - stats.mean_interval_s) * 0.8);
    } else if (stats.mean_interval_s > 110.0) {
        score -= std::min(25.0, (stats.mean_interval_s - 110.0) * 0.8);
    }
    if (stats.p90_interval_s > 180.0) {
        score -= std::min(20.0, (stats.p90_interval_s - 180.0) * 0.15);
    }
    if (stats.p99_interval_s > 420.0) {
        score -= std::min(15.0, (stats.p99_interval_s - 420.0) * 0.05);
    }
    score -= std::min(20.0, stats.mean_abs_error_s * 0.2);
    if (score < 0.0) score = 0.0;
    if (score > 100.0) score = 100.0;
    return static_cast<int>(std::round(score));
}

static std::string PowAlgorithmName(const Consensus::Params& consensus)
{
    return consensus.fMatMulPOW ? "matmul" :
        (consensus.fKAWPOW ? "kawpow" : "sha256d");
}

static arith_uint256 ScaleTargetForSolveTime(
    const arith_uint256& current_target,
    int64_t current_solve_time_ms,
    int64_t requested_solve_time_ms,
    const arith_uint256& pow_limit)
{
    if (current_solve_time_ms <= 0 || requested_solve_time_ms <= 0) {
        arith_uint256 bounded{current_target};
        if (bounded == 0) bounded = arith_uint256{1};
        if (bounded > pow_limit) bounded = pow_limit;
        return bounded;
    }
    const arith_uint256 max_uint{~arith_uint256{}};
    arith_uint256 scaled{current_target};
    if (scaled > (max_uint / static_cast<uint64_t>(current_solve_time_ms))) {
        scaled = max_uint;
    } else {
        scaled *= static_cast<uint64_t>(current_solve_time_ms);
    }
    scaled /= static_cast<uint64_t>(requested_solve_time_ms);
    if (scaled == 0) {
        scaled = arith_uint256{1};
    }
    if (scaled > pow_limit) {
        scaled = pow_limit;
    }
    return scaled;
}

static UniValue BuildSolvePipelineRuntimeProfile()
{
    const MatMulSolvePipelineStats stats = ProbeMatMulSolvePipelineStats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("async_prepare_enabled", stats.async_prepare_enabled);
    obj.pushKV("cpu_confirm_candidates", stats.cpu_confirm_candidates);
    obj.pushKV("prepared_inputs", stats.prepared_inputs);
    obj.pushKV("overlapped_prepares", stats.overlapped_prepares);
    obj.pushKV("async_prepare_submissions", stats.async_prepare_submissions);
    obj.pushKV("async_prepare_completions", stats.async_prepare_completions);
    obj.pushKV("async_prepare_worker_threads", static_cast<uint64_t>(stats.async_prepare_worker_threads));
    obj.pushKV("batch_size", static_cast<uint64_t>(stats.batch_size));
    obj.pushKV("batched_digest_requests", stats.batched_digest_requests);
    obj.pushKV("batched_nonce_attempts", stats.batched_nonce_attempts);
    return obj;
}

static double MicrosToMillis(const uint64_t micros)
{
    return static_cast<double>(micros) / 1000.0;
}

static double MeanMicrosToMillis(const uint64_t total_micros, const uint64_t count)
{
    if (count == 0) return 0.0;
    return MicrosToMillis(total_micros) / static_cast<double>(count);
}

static UniValue BuildSolveRuntimeProfile()
{
    const MatMulSolveRuntimeStats stats = ProbeMatMulSolveRuntimeStats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("attempts", stats.attempts);
    obj.pushKV("solved_attempts", stats.solved_attempts);
    obj.pushKV("failed_attempts", stats.failed_attempts);
    obj.pushKV("total_elapsed_ms", MicrosToMillis(stats.total_elapsed_us));
    obj.pushKV("mean_elapsed_ms", MeanMicrosToMillis(stats.total_elapsed_us, stats.attempts));
    obj.pushKV("last_elapsed_ms", MicrosToMillis(stats.last_elapsed_us));
    obj.pushKV("max_elapsed_ms", MicrosToMillis(stats.max_elapsed_us));
    return obj;
}

static UniValue BuildValidationRuntimeProfile()
{
    const MatMulValidationRuntimeStats stats = ProbeMatMulValidationRuntimeStats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("phase2_checks", stats.phase2_checks);
    obj.pushKV("freivalds_checks", stats.freivalds_checks);
    obj.pushKV("transcript_checks", stats.transcript_checks);
    obj.pushKV("successful_checks", stats.successful_checks);
    obj.pushKV("failed_checks", stats.failed_checks);
    obj.pushKV("total_phase2_elapsed_ms", MicrosToMillis(stats.total_phase2_elapsed_us));
    obj.pushKV("mean_phase2_elapsed_ms", MeanMicrosToMillis(stats.total_phase2_elapsed_us, stats.phase2_checks));
    obj.pushKV("last_phase2_elapsed_ms", MicrosToMillis(stats.last_phase2_elapsed_us));
    obj.pushKV("max_phase2_elapsed_ms", MicrosToMillis(stats.max_phase2_elapsed_us));
    obj.pushKV("total_freivalds_elapsed_ms", MicrosToMillis(stats.total_freivalds_elapsed_us));
    obj.pushKV("mean_freivalds_elapsed_ms", MeanMicrosToMillis(stats.total_freivalds_elapsed_us, stats.freivalds_checks));
    obj.pushKV("last_freivalds_elapsed_ms", MicrosToMillis(stats.last_freivalds_elapsed_us));
    obj.pushKV("max_freivalds_elapsed_ms", MicrosToMillis(stats.max_freivalds_elapsed_us));
    obj.pushKV("total_transcript_elapsed_ms", MicrosToMillis(stats.total_transcript_elapsed_us));
    obj.pushKV("mean_transcript_elapsed_ms", MeanMicrosToMillis(stats.total_transcript_elapsed_us, stats.transcript_checks));
    obj.pushKV("last_transcript_elapsed_ms", MicrosToMillis(stats.last_transcript_elapsed_us));
    obj.pushKV("max_transcript_elapsed_ms", MicrosToMillis(stats.max_transcript_elapsed_us));
    return obj;
}

static UniValue BuildPropagationProxyProfile(
    const ChainstateManager& chainman,
    const NodeContext& node) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const CChainParams& chainparams = chainman.GetParams();
    const ArgsManager& args = EnsureArgsman(node);
    const int64_t min_outbound_peers =
        args.GetIntArg("-miningminoutboundpeers", DefaultMinOutboundPeersForMiningTemplate(chainparams));
    const int64_t min_synced_outbound_peers =
        args.GetIntArg("-miningminsyncedoutboundpeers", DefaultMinSyncedOutboundPeersForMiningTemplate(chainparams));
    const int64_t max_peer_sync_height_lag =
        args.GetIntArg("-miningmaxpeersyncheightlag", DefaultMaxPeerSyncHeightLagForMiningTemplate(chainparams));
    const int64_t max_header_lag =
        args.GetIntArg("-miningmaxheaderlag", DefaultMaxHeaderLagForMiningTemplate(chainparams));

    const CBlockIndex* const active_tip = chainman.ActiveChain().Tip();
    const CBlockIndex* const best_header = chainman.m_best_header;
    const int validated_tip_height = active_tip != nullptr ? active_tip->nHeight : -1;
    const int best_header_height = best_header != nullptr ? best_header->nHeight : validated_tip_height;
    const int header_lag = std::max(0, best_header_height - validated_tip_height);

    size_t connected_peers{0};
    size_t outbound_peers{0};
    bool network_active{false};
    OutboundPeerDiagnosticsSummary outbound_diag;
    if (node.connman) {
        network_active = node.connman->GetNetworkActive();
        connected_peers = node.connman->GetNodeCount(ConnectionDirection::Both);
        outbound_peers = node.connman->GetNodeCount(ConnectionDirection::Out);
        if (active_tip != nullptr) {
            outbound_diag = CollectOutboundPeerDiagnostics(
                *node.connman,
                node.peerman.get(),
                active_tip->nHeight,
                max_peer_sync_height_lag);
        }
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("network_active", network_active);
    obj.pushKV("connected_peers", static_cast<uint64_t>(connected_peers));
    obj.pushKV("outbound_peers", static_cast<uint64_t>(outbound_peers));
    obj.pushKV("synced_outbound_peers", static_cast<uint64_t>(outbound_diag.synced_outbound_peers));
    obj.pushKV("manual_outbound_peers", static_cast<uint64_t>(outbound_diag.manual_outbound_peers));
    obj.pushKV(
        "outbound_peers_missing_sync_height",
        static_cast<uint64_t>(outbound_diag.outbound_peers_missing_sync_height));
    obj.pushKV(
        "outbound_peers_beyond_sync_lag",
        static_cast<uint64_t>(outbound_diag.outbound_peers_beyond_sync_lag));
    obj.pushKV(
        "recent_block_announcing_outbound_peers",
        static_cast<uint64_t>(outbound_diag.recent_block_announcing_outbound_peers));
    obj.pushKV("validated_tip_height", validated_tip_height);
    obj.pushKV("best_header_height", best_header_height);
    obj.pushKV("header_lag", header_lag);
    obj.pushKV("required_outbound_peers", min_outbound_peers);
    obj.pushKV("required_synced_outbound_peers", min_synced_outbound_peers);
    obj.pushKV("max_peer_sync_height_lag", max_peer_sync_height_lag);
    obj.pushKV("max_header_lag", max_header_lag);
    UniValue peer_details(UniValue::VARR);
    for (const OutboundPeerDiagnostic& peer : outbound_diag.peers) {
        UniValue detail(UniValue::VOBJ);
        detail.pushKV("addr", peer.addr);
        detail.pushKV("connection_type", peer.connection_type);
        detail.pushKV("manual", peer.manual);
        detail.pushKV("sync_height", peer.sync_height);
        detail.pushKV("common_height", peer.common_height);
        detail.pushKV("presync_height", peer.presync_height);
        detail.pushKV("starting_height", peer.starting_height);
        detail.pushKV("sync_lag", peer.sync_lag);
        detail.pushKV("last_block_time", peer.last_block_time);
        detail.pushKV("last_block_announcement", peer.last_block_announcement);
        detail.pushKV("counts_as_synced_outbound", peer.counts_as_synced_outbound);
        peer_details.push_back(std::move(detail));
    }
    obj.pushKV("outbound_peer_diagnostics", std::move(peer_details));
    return obj;
}

static UniValue BuildReorgProtectionProfile(const ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const Consensus::Params& consensus = chainman.GetConsensus();
    const CBlockIndex* const active_tip = chainman.ActiveChain().Tip();
    const int current_tip_height = active_tip != nullptr ? active_tip->nHeight : -1;
    const bool enabled =
        consensus.nMaxReorgDepth != std::numeric_limits<uint32_t>::max() &&
        consensus.nReorgProtectionStartHeight != std::numeric_limits<int32_t>::max();
    const auto stats = ProbeReorgProtectionRuntimeStats();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("enabled", enabled);
    obj.pushKV("active", enabled && current_tip_height >= consensus.nReorgProtectionStartHeight);
    obj.pushKV("current_tip_height", current_tip_height);
    obj.pushKV("start_height", enabled ? consensus.nReorgProtectionStartHeight : -1);
    obj.pushKV("max_reorg_depth", enabled ? static_cast<int64_t>(consensus.nMaxReorgDepth) : 0);
    obj.pushKV("rejected_reorgs", stats.rejected_reorgs);
    obj.pushKV("deepest_rejected_reorg_depth", static_cast<int64_t>(stats.deepest_rejected_reorg_depth));
    obj.pushKV("last_rejected_reorg_depth", static_cast<int64_t>(stats.last_rejected_reorg_depth));
    obj.pushKV("last_rejected_max_reorg_depth", static_cast<int64_t>(stats.last_rejected_max_reorg_depth));
    obj.pushKV("last_rejected_tip_height", stats.last_rejected_tip_height);
    obj.pushKV("last_rejected_fork_height", stats.last_rejected_fork_height);
    obj.pushKV("last_rejected_candidate_height", stats.last_rejected_candidate_height);
    obj.pushKV("last_rejected_unix", stats.last_rejected_unix);
    return obj;
}

static UniValue BuildConsensusGuardProfile(const CChain& active_chain, const Consensus::Params& consensus)
{
    const CBlockIndex* const active_tip = active_chain.Tip();
    const int current_tip_height = active_tip != nullptr ? active_tip->nHeight : -1;
    const int next_height =
        current_tip_height < std::numeric_limits<int>::max() ? current_tip_height + 1 : current_tip_height;
    const bool binding_configured =
        consensus.nMatMulFreivaldsBindingHeight != std::numeric_limits<int32_t>::max();
    const int activation_height = binding_configured ? consensus.nMatMulFreivaldsBindingHeight : -1;
    const bool binding_active = consensus.IsMatMulFreivaldsBindingActive(current_tip_height);
    const int remaining_blocks =
        (!binding_configured || binding_active || current_tip_height < 0)
            ? 0
            : std::max(0, activation_height - current_tip_height);

    UniValue obj(UniValue::VOBJ);
    UniValue binding(UniValue::VOBJ);
    binding.pushKV("active", binding_active);
    binding.pushKV("activation_height", activation_height);
    binding.pushKV("remaining_blocks", remaining_blocks);
    obj.pushKV("freivalds_transcript_binding", std::move(binding));
    const bool payload_required = consensus.IsMatMulProductPayloadRequired(next_height);
    const int payload_activation_height =
        consensus.fMatMulRequireProductPayload
            ? 0
            : (consensus.nMatMulProductDigestHeight != std::numeric_limits<int32_t>::max()
                ? consensus.nMatMulProductDigestHeight
                : -1);
    const int payload_remaining_blocks =
        (payload_activation_height < 0 || payload_required || current_tip_height < 0)
            ? 0
            : std::max(0, payload_activation_height - current_tip_height);
    UniValue payload_mining(UniValue::VOBJ);
    payload_mining.pushKV("enabled", ShouldIncludeMatMulFreivaldsPayloadForMining(next_height, consensus));
    payload_mining.pushKV("required_by_consensus", payload_required);
    payload_mining.pushKV("activation_height", payload_activation_height);
    payload_mining.pushKV("remaining_blocks", payload_remaining_blocks);
    obj.pushKV("freivalds_payload_mining", std::move(payload_mining));
    const MatMulAsertHalfLifeInfo half_life_info = GetMatMulAsertHalfLifeInfo(active_tip, consensus);
    const int half_life_remaining_blocks =
        (!half_life_info.upgrade_configured || half_life_info.upgrade_active || current_tip_height < 0)
            ? 0
            : std::max(0, half_life_info.upgrade_height - current_tip_height);
    UniValue asert_half_life(UniValue::VOBJ);
    asert_half_life.pushKV("current_s", half_life_info.current_half_life_s);
    asert_half_life.pushKV("current_anchor_height", half_life_info.current_anchor_height);
    asert_half_life.pushKV("upgrade_active", half_life_info.upgrade_active);
    asert_half_life.pushKV("upgrade_height", half_life_info.upgrade_configured ? half_life_info.upgrade_height : -1);
    asert_half_life.pushKV("upgrade_half_life_s", half_life_info.upgrade_half_life_s);
    asert_half_life.pushKV("remaining_blocks", half_life_remaining_blocks);
    obj.pushKV("asert_half_life", std::move(asert_half_life));
    const MatMulPreHashEpsilonBitsInfo prehash_info =
        GetMatMulPreHashEpsilonBitsInfo(current_tip_height, consensus);
    const int prehash_remaining_blocks =
        (!prehash_info.upgrade_configured || prehash_info.upgrade_active || current_tip_height < 0)
            ? 0
            : std::max(0, prehash_info.upgrade_height - current_tip_height);
    UniValue pre_hash_epsilon_bits(UniValue::VOBJ);
    pre_hash_epsilon_bits.pushKV("current_bits", static_cast<uint64_t>(prehash_info.current_bits));
    pre_hash_epsilon_bits.pushKV("next_block_bits", static_cast<uint64_t>(prehash_info.next_block_bits));
    pre_hash_epsilon_bits.pushKV("upgrade_active", prehash_info.upgrade_active);
    pre_hash_epsilon_bits.pushKV("upgrade_height", prehash_info.upgrade_configured ? prehash_info.upgrade_height : -1);
    pre_hash_epsilon_bits.pushKV("upgrade_bits", static_cast<uint64_t>(prehash_info.upgrade_bits));
    pre_hash_epsilon_bits.pushKV("remaining_blocks", prehash_remaining_blocks);
    obj.pushKV("pre_hash_epsilon_bits", std::move(pre_hash_epsilon_bits));
    return obj;
}

static UniValue ConsensusGuardAlerts(const CChain& active_chain, const Consensus::Params& consensus)
{
    UniValue alerts(UniValue::VARR);
    const CBlockIndex* const active_tip = active_chain.Tip();
    const int current_tip_height = active_tip != nullptr ? active_tip->nHeight : -1;
    if (consensus.fMatMulFreivaldsEnabled &&
        consensus.nMatMulFreivaldsBindingHeight != std::numeric_limits<int32_t>::max() &&
        !consensus.IsMatMulFreivaldsBindingActive(current_tip_height)) {
        alerts.push_back(strprintf(
            "freivalds transcript binding inactive until height %d",
            consensus.nMatMulFreivaldsBindingHeight));
    }
    const MatMulAsertHalfLifeInfo half_life_info = GetMatMulAsertHalfLifeInfo(active_tip, consensus);
    if (half_life_info.upgrade_configured && !half_life_info.upgrade_active && current_tip_height >= 0) {
        alerts.push_back(strprintf(
            "asert half-life upgrade inactive until height %d (%llds -> %llds)",
            half_life_info.upgrade_height,
            static_cast<long long>(consensus.nMatMulAsertHalfLife),
            static_cast<long long>(half_life_info.upgrade_half_life_s)));
    }
    const MatMulPreHashEpsilonBitsInfo prehash_info =
        GetMatMulPreHashEpsilonBitsInfo(current_tip_height, consensus);
    if (prehash_info.upgrade_configured && !prehash_info.upgrade_active && current_tip_height >= 0) {
        alerts.push_back(strprintf(
            "pre-hash epsilon upgrade inactive until height %d (%u -> %u bits)",
            prehash_info.upgrade_height,
            prehash_info.current_bits,
            prehash_info.upgrade_bits));
    }
    return alerts;
}

static UniValue BuildBackendRuntimeProfile()
{
    const auto stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("digest_requests", stats.digest_requests);
    obj.pushKV("requested_cpu", stats.requested_cpu);
    obj.pushKV("requested_metal", stats.requested_metal);
    obj.pushKV("requested_cuda", stats.requested_cuda);
    obj.pushKV("requested_unknown", stats.requested_unknown);
    obj.pushKV("metal_successes", stats.metal_successes);
    obj.pushKV("metal_fallbacks_to_cpu", stats.metal_fallbacks_to_cpu);
    obj.pushKV("metal_digest_mismatches", stats.metal_digest_mismatches);
    obj.pushKV("metal_retry_without_uploaded_base_attempts", stats.metal_retry_without_uploaded_base_attempts);
    obj.pushKV("metal_retry_without_uploaded_base_successes", stats.metal_retry_without_uploaded_base_successes);
    obj.pushKV("gpu_input_generation_attempts", stats.gpu_input_generation_attempts);
    obj.pushKV("gpu_input_generation_successes", stats.gpu_input_generation_successes);
    obj.pushKV("gpu_input_generation_failures", stats.gpu_input_generation_failures);
    obj.pushKV("gpu_input_auto_disabled_skips", stats.gpu_input_auto_disabled_skips);
    obj.pushKV("gpu_input_auto_disabled", stats.gpu_input_auto_disabled);
    obj.pushKV("last_metal_fallback_error", stats.last_metal_fallback_error);
    obj.pushKV("last_gpu_input_error", stats.last_gpu_input_error);
    return obj;
}

struct MatMulServiceDifficultyResolution;
static UniValue BuildMatMulServiceDifficultyResolution(
    const MatMulServiceDifficultyResolution& resolution);
static UniValue BuildMatMulOperatorCapacityPlan(
    double total_target_s,
    int solver_parallelism,
    double solver_duty_cycle_pct);

static constexpr int MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM{1};
static constexpr double MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT{100.0};

static UniValue BuildServiceProfile(
    const ChainstateManager& chainman,
    const NodeContext& node,
    double network_target_s,
    double solve_time_target_s,
    double validation_overhead_s,
    double propagation_overhead_s,
    const MatMulServiceDifficultyResolution* difficulty_resolution = nullptr,
    int solver_parallelism = 1,
    double solver_duty_cycle_pct = 100.0) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const double overhead_target_s = validation_overhead_s + propagation_overhead_s;
    const double total_target_s = solve_time_target_s + overhead_target_s;
    const double solve_share_pct = total_target_s > 0.0 ? (solve_time_target_s / total_target_s) * 100.0 : 0.0;
    const double validation_share_pct = total_target_s > 0.0 ? (validation_overhead_s / total_target_s) * 100.0 : 0.0;
    const double propagation_share_pct = total_target_s > 0.0 ? (propagation_overhead_s / total_target_s) * 100.0 : 0.0;

    UniValue runtime(UniValue::VOBJ);
    runtime.pushKV("solve_pipeline", BuildSolvePipelineRuntimeProfile());
    runtime.pushKV("solve_runtime", BuildSolveRuntimeProfile());
    runtime.pushKV("validation_runtime", BuildValidationRuntimeProfile());
    runtime.pushKV("propagation_proxy", BuildPropagationProxyProfile(chainman, node));
    runtime.pushKV("reorg_protection", BuildReorgProtectionProfile(chainman));
    runtime.pushKV("backend_runtime", BuildBackendRuntimeProfile());

    UniValue profile(UniValue::VOBJ);
    profile.pushKV("network_target_s", network_target_s);
    profile.pushKV("solve_time_target_s", solve_time_target_s);
    profile.pushKV("validation_overhead_s", validation_overhead_s);
    profile.pushKV("propagation_overhead_s", propagation_overhead_s);
    profile.pushKV("overhead_target_s", overhead_target_s);
    profile.pushKV("total_target_s", total_target_s);
    profile.pushKV("solve_share_pct", solve_share_pct);
    profile.pushKV("validation_share_pct", validation_share_pct);
    profile.pushKV("propagation_share_pct", propagation_share_pct);
    profile.pushKV("delta_from_network_s", solve_time_target_s - network_target_s);
    profile.pushKV(
        "operator_capacity",
        BuildMatMulOperatorCapacityPlan(
            total_target_s,
            solver_parallelism,
            solver_duty_cycle_pct));
    if (difficulty_resolution != nullptr) {
        profile.pushKV(
            "difficulty_resolution",
            BuildMatMulServiceDifficultyResolution(*difficulty_resolution));
    }
    profile.pushKV("runtime_observability", std::move(runtime));
    return profile;
}

struct MatMulWorkProfileOptions {
    std::string seed_derivation_scope{"per_parent_block"};
    std::string seed_derivation_rule{"sha256(prev_block_hash || height || which)"};
    bool winner_knows_next_seeds_first{true};
    bool publicly_precomputable_before_parent_seen{false};
    uint64_t public_precompute_horizon_blocks{0};
    std::vector<std::string> template_mutations_preserve_seed{"merkle_root", "nonce", "time"};
    bool sigma_gate_applied{true};
    std::string sigma_rule{"sigma <= target << epsilon_bits"};
    std::string digest_rule{"matmul_digest <= target"};
    int32_t pre_hash_epsilon_bits_override{-1};
};

static UniValue BuildMatMulWorkProfile(
    const CBlockHeader& challenge_header,
    const Consensus::Params& consensus,
    int32_t block_height,
    const MatMulWorkProfileOptions& options = {})
{
    const uint64_t n = static_cast<uint64_t>(challenge_header.matmul_dim);
    const uint64_t b = static_cast<uint64_t>(consensus.nMatMulTranscriptBlockSize);
    const uint64_t r = static_cast<uint64_t>(consensus.nMatMulNoiseRank);
    const uint64_t field_element_bytes = sizeof(matmul::field::Element);
    const uint64_t matrix_elements = n * n;
    const uint64_t matrix_bytes = matrix_elements * field_element_bytes;
    const uint64_t matrix_generation_elements_per_seed = matrix_elements;
    const uint64_t transcript_blocks_per_axis = b > 0 ? n / b : 0;
    const uint64_t transcript_block_multiplications =
        transcript_blocks_per_axis * transcript_blocks_per_axis * transcript_blocks_per_axis;
    const uint64_t transcript_field_muladds = n * n * n;
    const uint64_t compression_vector_elements = b * b;
    const uint64_t compression_field_muladds =
        transcript_block_multiplications * compression_vector_elements;
    const uint64_t noise_elements = 4 * n * r;
    const uint64_t noise_low_rank_muladds = 2 * n * n * r;
    const uint64_t denoise_field_muladds = 5 * n * n * r + 2 * n * r * r;
    const uint64_t per_nonce_total_field_muladds_estimate =
        transcript_field_muladds + compression_field_muladds + noise_low_rank_muladds;
    const double oracle_rejection_probability_per_element =
        1.0 / static_cast<double>(static_cast<uint64_t>(matmul::field::MODULUS) + 1);
    const uint64_t fixed_matrix_generation_elements_upper_bound = 2 * matrix_generation_elements_per_seed;
    const uint64_t fixed_clean_product_field_muladds_upper_bound = transcript_field_muladds;
    const uint64_t dynamic_per_nonce_field_muladds_lower_bound =
        compression_field_muladds + noise_low_rank_muladds;
    const double dynamic_per_nonce_share_lower_bound = per_nonce_total_field_muladds_estimate > 0
        ? static_cast<double>(dynamic_per_nonce_field_muladds_lower_bound) /
            static_cast<double>(per_nonce_total_field_muladds_estimate)
        : 0.0;
    const double reusable_work_share_upper_bound = per_nonce_total_field_muladds_estimate > 0
        ? static_cast<double>(fixed_clean_product_field_muladds_upper_bound) /
            static_cast<double>(per_nonce_total_field_muladds_estimate)
        : 0.0;
    const double amortization_advantage_upper_bound = dynamic_per_nonce_field_muladds_lower_bound > 0
        ? static_cast<double>(per_nonce_total_field_muladds_estimate) /
            static_cast<double>(dynamic_per_nonce_field_muladds_lower_bound)
        : 0.0;
    const uint32_t pre_hash_epsilon_bits = options.pre_hash_epsilon_bits_override >= 0
        ? static_cast<uint32_t>(options.pre_hash_epsilon_bits_override)
        : GetMatMulPreHashEpsilonBitsForHeight(consensus, block_height);
    const uint64_t sigma_target_multiplier_vs_digest_target = !options.sigma_gate_applied
        ? 1
        : (pre_hash_epsilon_bits >= 63 ? std::numeric_limits<uint64_t>::max() : (uint64_t{1} << pre_hash_epsilon_bits));
    double digest_target_probability_per_nonce_estimate{0.0};
    double sigma_pass_probability_per_nonce_estimate{0.0};
    double expected_sigma_passes_per_digest_hit_estimate{0.0};
    double expected_matmul_invocations_per_1m_nonces_estimate{0.0};
    bool target_multiplier_saturated{false};
    if (auto digest_target{DeriveTarget(challenge_header.nBits, consensus.powLimit)}) {
        arith_uint256 pre_hash_target{*digest_target};
        if (options.sigma_gate_applied && pre_hash_epsilon_bits > 0) {
            if (pre_hash_epsilon_bits >= 256) {
                pre_hash_target = ~arith_uint256(0);
                target_multiplier_saturated = (*digest_target != arith_uint256(0));
            } else {
                arith_uint256 mask = ~arith_uint256(0);
                mask >>= pre_hash_epsilon_bits;
                if (*digest_target > mask) {
                    pre_hash_target = ~arith_uint256(0);
                    target_multiplier_saturated = true;
                } else {
                    pre_hash_target = *digest_target << pre_hash_epsilon_bits;
                }
            }
        }
        constexpr double kTwoToMinus256 = 8.6361685550944446253863518628003995711160003644363e-78;
        digest_target_probability_per_nonce_estimate = std::min(1.0, digest_target->getdouble() * kTwoToMinus256);
        sigma_pass_probability_per_nonce_estimate = std::min(1.0, pre_hash_target.getdouble() * kTwoToMinus256);
        if (digest_target_probability_per_nonce_estimate > 0.0) {
            expected_sigma_passes_per_digest_hit_estimate =
                sigma_pass_probability_per_nonce_estimate / digest_target_probability_per_nonce_estimate;
        }
        expected_matmul_invocations_per_1m_nonces_estimate =
            sigma_pass_probability_per_nonce_estimate * 1'000'000.0;
    }

    UniValue profile(UniValue::VOBJ);
    profile.pushKV("field_element_bytes", field_element_bytes);
    profile.pushKV("matrix_elements", matrix_elements);
    profile.pushKV("matrix_bytes", matrix_bytes);
    profile.pushKV("matrix_generation_elements_per_seed", matrix_generation_elements_per_seed);
    profile.pushKV("transcript_blocks_per_axis", transcript_blocks_per_axis);
    profile.pushKV("transcript_block_multiplications", transcript_block_multiplications);
    profile.pushKV("transcript_field_muladds", transcript_field_muladds);
    profile.pushKV("compression_vector_elements", compression_vector_elements);
    profile.pushKV("compression_field_muladds", compression_field_muladds);
    profile.pushKV("noise_elements", noise_elements);
    profile.pushKV("noise_low_rank_muladds", noise_low_rank_muladds);
    profile.pushKV("denoise_field_muladds", denoise_field_muladds);
    profile.pushKV("per_nonce_total_field_muladds_estimate", per_nonce_total_field_muladds_estimate);
    profile.pushKV("oracle_rejection_probability_per_element", oracle_rejection_probability_per_element);
    profile.pushKV(
        "expected_oracle_retries_per_matrix_seed",
        static_cast<double>(matrix_generation_elements_per_seed) * oracle_rejection_probability_per_element);
    profile.pushKV(
        "expected_oracle_retries_per_nonce_noise",
        static_cast<double>(noise_elements) * oracle_rejection_probability_per_element);
    profile.pushKV("pre_hash_epsilon_bits", pre_hash_epsilon_bits);
    UniValue cross_nonce_reuse(UniValue::VOBJ);
    cross_nonce_reuse.pushKV("seed_scope", "per_block_template");
    cross_nonce_reuse.pushKV("sigma_scope", "per_nonce");
    cross_nonce_reuse.pushKV("fixed_instance_reuse_possible", true);
    cross_nonce_reuse.pushKV("fixed_matrix_generation_elements_upper_bound", fixed_matrix_generation_elements_upper_bound);
    cross_nonce_reuse.pushKV("fixed_clean_product_field_muladds_upper_bound", fixed_clean_product_field_muladds_upper_bound);
    cross_nonce_reuse.pushKV("dynamic_per_nonce_field_muladds_lower_bound", dynamic_per_nonce_field_muladds_lower_bound);
    cross_nonce_reuse.pushKV("dynamic_per_nonce_share_lower_bound", dynamic_per_nonce_share_lower_bound);
    cross_nonce_reuse.pushKV("reusable_work_share_upper_bound", reusable_work_share_upper_bound);
    cross_nonce_reuse.pushKV("amortization_advantage_upper_bound", amortization_advantage_upper_bound);
    UniValue next_block_seed_access(UniValue::VOBJ);
    next_block_seed_access.pushKV("seed_derivation_scope", options.seed_derivation_scope);
    next_block_seed_access.pushKV("seed_derivation_rule", options.seed_derivation_rule);
    next_block_seed_access.pushKV("winner_knows_next_seeds_first", options.winner_knows_next_seeds_first);
    next_block_seed_access.pushKV("publicly_precomputable_before_parent_seen", options.publicly_precomputable_before_parent_seen);
    next_block_seed_access.pushKV("public_precompute_horizon_blocks", options.public_precompute_horizon_blocks);
    next_block_seed_access.pushKV(
        "fixed_matrix_generation_elements_upper_bound",
        fixed_matrix_generation_elements_upper_bound);
    UniValue template_mutations_preserve_seed(UniValue::VARR);
    for (const std::string& field : options.template_mutations_preserve_seed) {
        template_mutations_preserve_seed.push_back(field);
    }
    next_block_seed_access.pushKV(
        "template_mutations_preserve_seed",
        std::move(template_mutations_preserve_seed));
    UniValue pre_hash_lottery(UniValue::VOBJ);
    pre_hash_lottery.pushKV("consensus_enforced", options.sigma_gate_applied);
    pre_hash_lottery.pushKV("sigma_rule", options.sigma_rule);
    pre_hash_lottery.pushKV("digest_rule", options.digest_rule);
    pre_hash_lottery.pushKV("epsilon_bits", pre_hash_epsilon_bits);
    pre_hash_lottery.pushKV(
        "sigma_target_multiplier_vs_digest_target",
        sigma_target_multiplier_vs_digest_target);
    pre_hash_lottery.pushKV(
        "digest_target_probability_per_nonce_estimate",
        digest_target_probability_per_nonce_estimate);
    pre_hash_lottery.pushKV(
        "sigma_pass_probability_per_nonce_estimate",
        sigma_pass_probability_per_nonce_estimate);
    pre_hash_lottery.pushKV(
        "expected_sigma_passes_per_digest_hit_estimate",
        expected_sigma_passes_per_digest_hit_estimate);
    pre_hash_lottery.pushKV(
        "expected_matmul_invocations_per_1m_nonces_estimate",
        expected_matmul_invocations_per_1m_nonces_estimate);
    pre_hash_lottery.pushKV("target_multiplier_saturated", target_multiplier_saturated);
    profile.pushKV("cross_nonce_reuse", std::move(cross_nonce_reuse));
    profile.pushKV("next_block_seed_access", std::move(next_block_seed_access));
    profile.pushKV("pre_hash_lottery", std::move(pre_hash_lottery));
    return profile;
}

static UniValue BuildMatMulChallengeResponse(
    ChainstateManager& chainman,
    const NodeContext& node,
    double solve_time_target_s,
    double validation_overhead_s,
    double propagation_overhead_s,
    const MatMulServiceDifficultyResolution* difficulty_resolution = nullptr,
    int solver_parallelism = 1,
    double solver_duty_cycle_pct = 100.0)
{
    const std::string chain_name = chainman.GetParams().GetChainTypeString();
    const Consensus::Params& consensus = chainman.GetConsensus();
    Mining& miner = EnsureMining(node);
    std::unique_ptr<BlockTemplate> block_template = miner.createNewBlock();
    CHECK_NONFATAL(block_template);

    CBlockHeader challenge_header{block_template->getBlockHeader()};
    const CBlockIndex* pindex_prev{nullptr};
    int next_height{0};
    int64_t mintime{0};
    {
        LOCK(cs_main);
        pindex_prev = chainman.m_blockman.LookupBlockIndex(challenge_header.hashPrevBlock);
        CHECK_NONFATAL(pindex_prev != nullptr);
        if (!TryGetNextBlockHeight(pindex_prev, next_height)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "next block height overflow");
        }
        UpdateTime(&challenge_header, consensus, pindex_prev);
        mintime = GetMinimumTime(pindex_prev, consensus);
    }
    challenge_header.nNonce64 = 0;
    challenge_header.nNonce = 0;
    challenge_header.mix_hash.SetNull();
    challenge_header.matmul_digest.SetNull();
    if (challenge_header.matmul_dim == 0) {
        challenge_header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    }
    if (challenge_header.seed_a.IsNull()) {
        challenge_header.seed_a = DeterministicMatMulSeed(challenge_header.hashPrevBlock, static_cast<uint32_t>(next_height), 0);
    }
    if (challenge_header.seed_b.IsNull()) {
        challenge_header.seed_b = DeterministicMatMulSeed(challenge_header.hashPrevBlock, static_cast<uint32_t>(next_height), 1);
    }

    CBlockIndex next_index;
    next_index.pprev = const_cast<CBlockIndex*>(pindex_prev);
    next_index.nHeight = next_height;
    next_index.nTime = challenge_header.nTime;
    next_index.nBits = challenge_header.nBits;

    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const arith_uint256 current_target{*CHECK_NONFATAL(DeriveTarget(next_index.nBits, consensus.powLimit))};
    const int64_t current_solve_time_ms = static_cast<int64_t>(std::llround(consensus.nPowTargetSpacing * 1000.0));
    const int64_t requested_solve_time_ms = static_cast<int64_t>(std::llround(solve_time_target_s * 1000.0));
    const arith_uint256 profiled_target = ScaleTargetForSolveTime(
        current_target,
        current_solve_time_ms,
        requested_solve_time_ms,
        pow_limit);
    const uint32_t profiled_bits =
        requested_solve_time_ms == current_solve_time_ms ? next_index.nBits : profiled_target.GetCompact();

    CBlockIndex profiled_index;
    profiled_index.pprev = pindex_prev ? const_cast<CBlockIndex*>(pindex_prev) : next_index.pprev;
    profiled_index.nHeight = next_height;
    profiled_index.nTime = challenge_header.nTime;
    profiled_index.nBits = profiled_bits;
    challenge_header.nBits = profiled_bits;

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", chain_name);
    obj.pushKV("algorithm", "matmul");
    obj.pushKV("height", profiled_index.nHeight);
    obj.pushKV("previousblockhash", challenge_header.hashPrevBlock.GetHex());
    obj.pushKV("mintime", mintime);
    obj.pushKV("bits", strprintf("%08x", profiled_index.nBits));
    obj.pushKV("difficulty", GetDifficulty(profiled_index));
    obj.pushKV("target", GetTarget(profiled_index, consensus.powLimit).GetHex());
    obj.pushKV("noncerange", "0000000000000000ffffffffffffffff");

    UniValue header_context(UniValue::VOBJ);
    header_context.pushKV("version", challenge_header.nVersion);
    header_context.pushKV("previousblockhash", challenge_header.hashPrevBlock.GetHex());
    header_context.pushKV("merkleroot", challenge_header.hashMerkleRoot.GetHex());
    header_context.pushKV("time", challenge_header.GetBlockTime());
    header_context.pushKV("bits", strprintf("%08x", challenge_header.nBits));
    header_context.pushKV("nonce64_start", static_cast<uint64_t>(challenge_header.nNonce64));
    header_context.pushKV("matmul_dim", static_cast<uint64_t>(challenge_header.matmul_dim));
    header_context.pushKV("seed_a", challenge_header.seed_a.GetHex());
    header_context.pushKV("seed_b", challenge_header.seed_b.GetHex());
    obj.pushKV("header_context", std::move(header_context));

    UniValue matmul(UniValue::VOBJ);
    matmul.pushKV("n", static_cast<uint64_t>(challenge_header.matmul_dim));
    matmul.pushKV("b", static_cast<uint64_t>(consensus.nMatMulTranscriptBlockSize));
    matmul.pushKV("r", static_cast<uint64_t>(consensus.nMatMulNoiseRank));
    matmul.pushKV("q", static_cast<uint64_t>(consensus.nMatMulFieldModulus));
    matmul.pushKV("min_dimension", static_cast<uint64_t>(consensus.nMatMulMinDimension));
    matmul.pushKV("max_dimension", static_cast<uint64_t>(consensus.nMatMulMaxDimension));
    matmul.pushKV("seed_a", challenge_header.seed_a.GetHex());
    matmul.pushKV("seed_b", challenge_header.seed_b.GetHex());
    obj.pushKV("matmul", std::move(matmul));
    obj.pushKV("work_profile", BuildMatMulWorkProfile(challenge_header, consensus, next_height));
    UniValue service_profile(UniValue::VOBJ);
    {
        LOCK(cs_main);
        service_profile = BuildServiceProfile(
            chainman,
            node,
            static_cast<double>(consensus.nPowTargetSpacing),
            solve_time_target_s,
            validation_overhead_s,
            propagation_overhead_s,
            difficulty_resolution,
            solver_parallelism,
            solver_duty_cycle_pct);
    }
    obj.pushKV("service_profile", std::move(service_profile));
    return obj;
}

static constexpr char MATMUL_SERVICE_KIND[] = "matmul_service_challenge_v1";
static constexpr char MATMUL_SERVICE_DOMAIN[] = "BTX_MATMUL_SERVICE_V1";
static constexpr int64_t MATMUL_SERVICE_MAX_EXPIRY_S{86'400};
static constexpr size_t MATMUL_SERVICE_MAX_TEXT_BYTES{256};
static constexpr double MATMUL_SERVICE_PROFILE_DEFAULT_MIN_SOLVE_TIME_S{0.25};
static constexpr double MATMUL_SERVICE_PROFILE_DEFAULT_MAX_SOLVE_TIME_S{30.0};
static constexpr char MATMUL_SERVICE_CHALLENGE_ID_RULE[] =
    "sha256(domain || binding_hash || salt || anchor_hash || anchor_height || issued_at || expires_at || target_solve_ms || validation_overhead_ms || propagation_overhead_ms)";
static constexpr char MATMUL_SERVICE_SEED_DERIVATION_RULE[] =
    "sha256(challenge_id || anchor_hash || label)";
static constexpr char MATMUL_SERVICE_VERIFICATION_RULE[] =
    "matmul_digest <= target && transcript_hash == digest";
static constexpr char MATMUL_SERVICE_REDEEM_RPC[] = "redeemmatmulserviceproof";
static constexpr char MATMUL_SERVICE_SOLVE_RPC[] = "solvematmulservicechallenge";
static constexpr char MATMUL_SERVICE_ISSUED_STORE_LOCAL_PERSISTENT_FILE[] = "local_persistent_file";
static constexpr char MATMUL_SERVICE_ISSUED_STORE_SHARED_FILE_LOCK_STORE[] = "shared_file_lock_store";
static constexpr char MATMUL_SERVICE_ISSUED_SCOPE_NODE_LOCAL[] = "node_local";
static constexpr char MATMUL_SERVICE_ISSUED_SCOPE_SHARED_FILE[] = "shared_file";
static constexpr char MATMUL_SERVICE_REGISTRY_FILENAME[] = "matmul_service_challenges.dat";
static constexpr uint64_t MATMUL_SERVICE_REGISTRY_DISK_VERSION{1};
static constexpr size_t MATMUL_SERVICE_ISSUED_CACHE_CAPACITY{10'000};
static constexpr size_t MATMUL_SERVICE_MAX_BATCH_SIZE{256};
static constexpr auto MATMUL_SERVICE_REGISTRY_LOCK_WAIT = std::chrono::milliseconds{25};
static constexpr size_t MATMUL_SERVICE_REGISTRY_LOCK_ATTEMPTS{200};
static constexpr char MATMUL_SERVICE_CHALLENGE_RPC[] = "getmatmulservicechallenge";
static constexpr char MATMUL_SERVICE_CHALLENGE_PLAN_RPC[] = "getmatmulservicechallengeplan";
static constexpr char MATMUL_SERVICE_CHALLENGE_PROFILE_RPC[] = "getmatmulservicechallengeprofile";
static constexpr char MATMUL_SERVICE_CHALLENGE_PROFILES_RPC[] = "listmatmulservicechallengeprofiles";
static constexpr char MATMUL_SERVICE_CHALLENGE_PROFILE_ISSUE_RPC[] = "issuematmulservicechallengeprofile";
static constexpr char MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED[] = "fixed";
static constexpr char MATMUL_SERVICE_DIFFICULTY_POLICY_ADAPTIVE_WINDOW[] = "adaptive_window";
static constexpr char MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_HOUR[] = "solves_per_hour";
static constexpr char MATMUL_SERVICE_OBJECTIVE_CHALLENGES_PER_HOUR[] = "challenges_per_hour";
static constexpr char MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_DAY[] = "solves_per_day";
static constexpr char MATMUL_SERVICE_OBJECTIVE_CHALLENGES_PER_DAY[] = "challenges_per_day";
static constexpr char MATMUL_SERVICE_OBJECTIVE_MEAN_SECONDS_BETWEEN_SOLVES[] = "mean_seconds_between_solves";
static constexpr char MATMUL_SERVICE_OBJECTIVE_MEAN_SECONDS_BETWEEN_CHALLENGES[] = "mean_seconds_between_challenges";
static constexpr int MATMUL_SERVICE_DIFFICULTY_POLICY_DEFAULT_WINDOW_BLOCKS{24};
static constexpr char MATMUL_SERVICE_REGISTRY_STATUS_NOT_LOADED[] = "not_loaded";
static constexpr char MATMUL_SERVICE_REGISTRY_STATUS_OK[] = "ok";
static constexpr char MATMUL_SERVICE_REGISTRY_STATUS_MISSING[] = "missing";
static constexpr char MATMUL_SERVICE_REGISTRY_STATUS_CORRUPT_QUARANTINED[] = "corrupt_quarantined";
static constexpr char MATMUL_SERVICE_REGISTRY_STATUS_UNSUPPORTED_VERSION_QUARANTINED[] = "unsupported_version_quarantined";
static constexpr char MATMUL_SERVICE_REGISTRY_STATUS_QUARANTINE_FAILED[] = "quarantine_failed";
static constexpr char MATMUL_SERVICE_VERIFY_LOOKUP_LOCAL_STATUS[] = "include_local_registry_status";

struct MatMulServiceDifficultyProfileSpec {
    const char* name;
    const char* difficulty_label;
    const char* description;
    int effort_tier;
    double solve_time_ratio;
};

static constexpr std::array<MatMulServiceDifficultyProfileSpec, 4>
    MATMUL_SERVICE_DIFFICULTY_PROFILE_SPECS{{
        {
            "interactive",
            "easy",
            "Low-friction challenge budget for human-facing endpoints and average nodes.",
            1,
            1.0 / 90.0,
        },
        {
            "balanced",
            "normal",
            "Default service gate for average nodes and low-latency API admission control.",
            2,
            1.0 / 45.0,
        },
        {
            "strict",
            "hard",
            "Higher-abuse gate for signups, posting, and costlier service operations.",
            3,
            1.0 / 18.0,
        },
        {
            "background",
            "idle",
            "Longer-running work budget for background agents and idle-time mining-style workflows.",
            4,
            1.0 / 9.0,
        },
    }};

struct MatMulServiceDifficultyRecommendation {
    std::string profile_name;
    std::string difficulty_label;
    std::string description;
    int effort_tier{0};
    double network_target_s{0.0};
    double solve_time_ratio{0.0};
    double unclamped_solve_time_s{0.0};
    double recommended_solve_time_s{0.0};
    double min_solve_time_s{0.0};
    double max_solve_time_s{0.0};
    double solve_time_multiplier{0.0};
    bool clamped{false};
};

struct MatMulServiceDifficultyResolution {
    std::string mode;
    double base_solve_time_s{0.0};
    double adjusted_solve_time_s{0.0};
    double resolved_solve_time_s{0.0};
    double min_solve_time_s{0.0};
    double max_solve_time_s{0.0};
    int window_blocks{0};
    size_t observed_interval_count{0};
    double observed_mean_interval_s{0.0};
    double network_target_s{0.0};
    double interval_scale{1.0};
    bool clamped{false};
};

struct MatMulResolvedServiceDifficultyProfile {
    MatMulServiceDifficultyRecommendation recommendation;
    MatMulServiceDifficultyResolution resolution;
};

struct MatMulOperatorCapacityPlan {
    std::string estimation_basis{"average_node"};
    int solver_parallelism{MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM};
    double solver_duty_cycle_pct{MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT};
    double effective_parallelism{1.0};
    double budgeted_solver_seconds_per_hour{3600.0};
    double estimated_sustained_solves_per_hour{0.0};
    double estimated_sustained_solves_per_day{0.0};
    double estimated_mean_seconds_between_solves{0.0};
};

struct MatMulServicePlanningObjective {
    std::string mode;
    double requested_value{0.0};
    double requested_sustained_solves_per_hour{0.0};
    double requested_sustained_solves_per_day{0.0};
    double requested_mean_seconds_between_solves{0.0};
    double requested_total_target_s{0.0};
    double requested_resolved_solve_time_s{0.0};
};

struct MatMulServicePlanningGap {
    double actual_value{0.0};
    double delta_value{0.0};
    double delta_pct{0.0};
    double actual_total_target_s{0.0};
    double total_target_delta_s{0.0};
    double actual_sustained_solves_per_hour{0.0};
    double actual_sustained_solves_per_day{0.0};
    double actual_mean_seconds_between_solves{0.0};
    double required_effective_parallelism{0.0};
    double available_effective_parallelism{0.0};
    double effective_parallelism_gap{0.0};
    double headroom_pct{0.0};
    bool objective_satisfied{false};
};

struct MatMulServicePlanningProfileCandidate {
    MatMulResolvedServiceDifficultyProfile resolved_profile;
    MatMulOperatorCapacityPlan operator_capacity;
    MatMulServicePlanningGap gap;
    double resolved_total_target_s{0.0};
};

struct MatMulServiceChallengeContext {
    std::string chain;
    std::string purpose;
    std::string resource;
    std::string subject;
    uint256 resource_hash;
    uint256 subject_hash;
    uint256 binding_hash;
    uint256 salt;
    uint256 challenge_id;
    uint256 anchor_hash;
    int anchor_height{0};
    int64_t issued_at{0};
    int64_t expires_at{0};
    double solve_time_target_s{0.0};
    std::string difficulty_policy;
    double base_solve_time_s{0.0};
    double adjusted_solve_time_s{0.0};
    double min_solve_time_s{0.0};
    double max_solve_time_s{0.0};
    int difficulty_window_blocks{0};
    size_t observed_interval_count{0};
    double observed_mean_interval_s{0.0};
    double network_target_s{0.0};
    double interval_scale{1.0};
    bool difficulty_clamped{false};
    double validation_overhead_s{0.0};
    double propagation_overhead_s{0.0};
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    CBlockHeader header;
    arith_uint256 target;
};

static const MatMulServiceDifficultyProfileSpec& GetMatMulServiceDifficultyProfileSpec(
    std::string_view name)
{
    for (const auto& spec : MATMUL_SERVICE_DIFFICULTY_PROFILE_SPECS) {
        if (spec.name == name || spec.difficulty_label == name) {
            return spec;
        }
    }
    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf(
            "unknown service challenge profile '%s' (expected interactive/easy, balanced/normal, strict/hard, or background/idle)",
            std::string{name}));
}

static MatMulServiceDifficultyRecommendation RecommendMatMulServiceDifficultyProfile(
    const Consensus::Params& consensus,
    std::string_view profile_name,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier)
{
    if (!(min_solve_time_s > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "min_solve_time_s must be positive");
    }
    if (!(max_solve_time_s > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_solve_time_s must be positive");
    }
    if (max_solve_time_s < min_solve_time_s) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_solve_time_s must be greater than or equal to min_solve_time_s");
    }
    if (!(solve_time_multiplier > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "solve_time_multiplier must be positive");
    }

    const auto& spec = GetMatMulServiceDifficultyProfileSpec(profile_name);
    MatMulServiceDifficultyRecommendation recommendation;
    recommendation.profile_name = spec.name;
    recommendation.difficulty_label = spec.difficulty_label;
    recommendation.description = spec.description;
    recommendation.effort_tier = spec.effort_tier;
    recommendation.network_target_s = static_cast<double>(consensus.nPowTargetSpacing);
    recommendation.solve_time_ratio = spec.solve_time_ratio;
    recommendation.unclamped_solve_time_s =
        recommendation.network_target_s * recommendation.solve_time_ratio * solve_time_multiplier;
    recommendation.recommended_solve_time_s = std::clamp(
        recommendation.unclamped_solve_time_s,
        min_solve_time_s,
        max_solve_time_s);
    recommendation.min_solve_time_s = min_solve_time_s;
    recommendation.max_solve_time_s = max_solve_time_s;
    recommendation.solve_time_multiplier = solve_time_multiplier;
    recommendation.clamped =
        recommendation.recommended_solve_time_s != recommendation.unclamped_solve_time_s;
    return recommendation;
}

static std::string ParseMatMulServiceDifficultyPolicy(std::string_view mode)
{
    if (mode.empty() || mode == MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED) {
        return MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED;
    }
    if (mode == MATMUL_SERVICE_DIFFICULTY_POLICY_ADAPTIVE_WINDOW) {
        return MATMUL_SERVICE_DIFFICULTY_POLICY_ADAPTIVE_WINDOW;
    }
    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf(
            "unknown difficulty_policy '%s' (expected fixed or adaptive_window)",
            std::string{mode}));
}

static MatMulServiceDifficultyResolution ResolveMatMulServiceDifficultyPolicy(
    const Consensus::Params& consensus,
    const CBlockIndex* anchor_tip,
    std::string_view mode,
    double base_solve_time_s,
    int window_blocks,
    double min_solve_time_s,
    double max_solve_time_s)
{
    if (!(base_solve_time_s > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "target_solve_time_s must be positive");
    }
    if (window_blocks <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "difficulty_window_blocks must be positive");
    }
    if (!(min_solve_time_s > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "min_solve_time_s must be positive");
    }
    if (!(max_solve_time_s > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_solve_time_s must be positive");
    }
    if (max_solve_time_s < min_solve_time_s) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "max_solve_time_s must be greater than or equal to min_solve_time_s");
    }

    MatMulServiceDifficultyResolution resolution;
    resolution.mode = ParseMatMulServiceDifficultyPolicy(mode);
    resolution.base_solve_time_s = base_solve_time_s;
    resolution.adjusted_solve_time_s = base_solve_time_s;
    resolution.resolved_solve_time_s = base_solve_time_s;
    resolution.min_solve_time_s = min_solve_time_s;
    resolution.max_solve_time_s = max_solve_time_s;
    resolution.window_blocks = window_blocks;
    resolution.network_target_s = static_cast<double>(consensus.nPowTargetSpacing);
    resolution.observed_mean_interval_s = resolution.network_target_s;

    if (resolution.mode == MATMUL_SERVICE_DIFFICULTY_POLICY_ADAPTIVE_WINDOW) {
        const auto stats = ComputeRecentIntervalStatsFromTip(
            anchor_tip,
            window_blocks,
            resolution.network_target_s);
        resolution.observed_interval_count = stats.count;
        if (stats.count > 0 && stats.mean_interval_s > 0.0) {
            resolution.observed_mean_interval_s = stats.mean_interval_s;
            resolution.interval_scale = stats.mean_interval_s / resolution.network_target_s;
        }
        resolution.adjusted_solve_time_s =
            resolution.base_solve_time_s * resolution.interval_scale;
    }
    resolution.resolved_solve_time_s = std::clamp(
        resolution.adjusted_solve_time_s,
        resolution.min_solve_time_s,
        resolution.max_solve_time_s);
    resolution.clamped =
        resolution.resolved_solve_time_s != resolution.adjusted_solve_time_s;
    return resolution;
}

static MatMulResolvedServiceDifficultyProfile ResolveMatMulServiceDifficultyProfile(
    ChainstateManager& chainman,
    std::string_view profile_name,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    std::string_view difficulty_policy,
    int difficulty_window_blocks)
{
    MatMulResolvedServiceDifficultyProfile result;
    result.recommendation = RecommendMatMulServiceDifficultyProfile(
        chainman.GetConsensus(),
        profile_name,
        min_solve_time_s,
        max_solve_time_s,
        solve_time_multiplier);
    const CBlockIndex* active_tip = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip());
    result.resolution = ResolveMatMulServiceDifficultyPolicy(
        chainman.GetConsensus(),
        active_tip,
        difficulty_policy,
        result.recommendation.recommended_solve_time_s,
        difficulty_window_blocks,
        min_solve_time_s,
        max_solve_time_s);
    return result;
}

static MatMulOperatorCapacityPlan ResolveMatMulOperatorCapacityPlan(
    double total_target_s,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    if (solver_parallelism <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "solver_parallelism must be positive");
    }
    if (!(solver_duty_cycle_pct > 0.0) || solver_duty_cycle_pct > 100.0) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "solver_duty_cycle_pct must be greater than 0 and less than or equal to 100");
    }

    MatMulOperatorCapacityPlan plan;
    plan.solver_parallelism = solver_parallelism;
    plan.solver_duty_cycle_pct = solver_duty_cycle_pct;
    plan.effective_parallelism =
        static_cast<double>(solver_parallelism) * (solver_duty_cycle_pct / 100.0);
    plan.budgeted_solver_seconds_per_hour = 3600.0 * plan.effective_parallelism;
    if (total_target_s > 0.0) {
        plan.estimated_sustained_solves_per_hour =
            plan.budgeted_solver_seconds_per_hour / total_target_s;
        plan.estimated_sustained_solves_per_day =
            plan.estimated_sustained_solves_per_hour * 24.0;
        plan.estimated_mean_seconds_between_solves =
            3600.0 / plan.estimated_sustained_solves_per_hour;
    }
    return plan;
}

static std::string ParseMatMulServicePlanningObjectiveMode(std::string_view mode)
{
    if (mode.empty() ||
        mode == MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_HOUR ||
        mode == MATMUL_SERVICE_OBJECTIVE_CHALLENGES_PER_HOUR) {
        return MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_HOUR;
    }
    if (mode == MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_DAY ||
        mode == MATMUL_SERVICE_OBJECTIVE_CHALLENGES_PER_DAY) {
        return MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_DAY;
    }
    if (mode == MATMUL_SERVICE_OBJECTIVE_MEAN_SECONDS_BETWEEN_SOLVES ||
        mode == MATMUL_SERVICE_OBJECTIVE_MEAN_SECONDS_BETWEEN_CHALLENGES) {
        return MATMUL_SERVICE_OBJECTIVE_MEAN_SECONDS_BETWEEN_SOLVES;
    }
    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf(
            "unknown objective_mode '%s' (expected solves_per_hour, solves_per_day, or mean_seconds_between_solves)",
            std::string{mode}));
}

static MatMulServicePlanningObjective ResolveMatMulServicePlanningObjective(
    std::string_view objective_mode,
    double objective_value,
    double validation_overhead_s,
    double propagation_overhead_s,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    const auto capacity_budget = ResolveMatMulOperatorCapacityPlan(
        0.0,
        solver_parallelism,
        solver_duty_cycle_pct);
    const std::string mode = ParseMatMulServicePlanningObjectiveMode(objective_mode);
    if (!(objective_value > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "objective_value must be positive");
    }

    MatMulServicePlanningObjective objective;
    objective.mode = mode;
    objective.requested_value = objective_value;
    if (mode == MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_HOUR) {
        objective.requested_sustained_solves_per_hour = objective_value;
        objective.requested_sustained_solves_per_day = objective_value * 24.0;
        objective.requested_mean_seconds_between_solves = 3600.0 / objective_value;
        objective.requested_total_target_s =
            capacity_budget.budgeted_solver_seconds_per_hour / objective_value;
    } else if (mode == MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_DAY) {
        objective.requested_sustained_solves_per_day = objective_value;
        objective.requested_sustained_solves_per_hour = objective_value / 24.0;
        objective.requested_mean_seconds_between_solves = 86400.0 / objective_value;
        objective.requested_total_target_s =
            (capacity_budget.budgeted_solver_seconds_per_hour * 24.0) / objective_value;
    } else {
        objective.requested_mean_seconds_between_solves = objective_value;
        objective.requested_sustained_solves_per_hour = 3600.0 / objective_value;
        objective.requested_sustained_solves_per_day = 86400.0 / objective_value;
        objective.requested_total_target_s =
            objective_value * capacity_budget.effective_parallelism;
    }

    objective.requested_resolved_solve_time_s =
        objective.requested_total_target_s - validation_overhead_s - propagation_overhead_s;
    if (!(objective.requested_resolved_solve_time_s > 0.0)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "objective_value leaves no positive solve budget after validation_overhead_s and propagation_overhead_s");
    }
    return objective;
}

static double ResolveMatMulServiceObjectiveBaseSolveTime(
    const Consensus::Params& consensus,
    const CBlockIndex* anchor_tip,
    std::string_view difficulty_policy,
    double resolved_solve_time_s,
    int difficulty_window_blocks)
{
    const std::string mode = ParseMatMulServiceDifficultyPolicy(difficulty_policy);
    if (mode != MATMUL_SERVICE_DIFFICULTY_POLICY_ADAPTIVE_WINDOW) {
        return resolved_solve_time_s;
    }
    const double network_target_s = static_cast<double>(consensus.nPowTargetSpacing);
    const auto stats = ComputeRecentIntervalStatsFromTip(
        anchor_tip,
        difficulty_window_blocks,
        network_target_s);
    double interval_scale{1.0};
    if (stats.count > 0 && stats.mean_interval_s > 0.0) {
        interval_scale = stats.mean_interval_s / network_target_s;
    }
    return resolved_solve_time_s / interval_scale;
}

static MatMulServicePlanningGap BuildMatMulServicePlanningGap(
    const MatMulServicePlanningObjective& objective,
    const MatMulOperatorCapacityPlan& operator_capacity,
    double resolved_total_target_s)
{
    MatMulServicePlanningGap gap;
    gap.actual_total_target_s = resolved_total_target_s;
    gap.total_target_delta_s =
        resolved_total_target_s - objective.requested_total_target_s;
    gap.actual_sustained_solves_per_hour =
        operator_capacity.estimated_sustained_solves_per_hour;
    gap.actual_sustained_solves_per_day =
        operator_capacity.estimated_sustained_solves_per_day;
    gap.actual_mean_seconds_between_solves =
        operator_capacity.estimated_mean_seconds_between_solves;
    gap.required_effective_parallelism =
        objective.requested_sustained_solves_per_hour > 0.0
            ? (objective.requested_sustained_solves_per_hour * resolved_total_target_s) / 3600.0
            : 0.0;
    gap.available_effective_parallelism = operator_capacity.effective_parallelism;
    gap.effective_parallelism_gap =
        gap.available_effective_parallelism - gap.required_effective_parallelism;
    gap.headroom_pct =
        objective.requested_sustained_solves_per_hour > 0.0
            ? ((gap.actual_sustained_solves_per_hour / objective.requested_sustained_solves_per_hour) - 1.0) * 100.0
            : 0.0;
    gap.objective_satisfied = gap.headroom_pct >= -0.0001;

    if (objective.mode == MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_HOUR) {
        gap.actual_value = gap.actual_sustained_solves_per_hour;
        gap.delta_value =
            gap.actual_value - objective.requested_sustained_solves_per_hour;
        gap.delta_pct =
            objective.requested_sustained_solves_per_hour > 0.0
                ? (gap.delta_value / objective.requested_sustained_solves_per_hour) * 100.0
                : 0.0;
    } else if (objective.mode == MATMUL_SERVICE_OBJECTIVE_SOLVES_PER_DAY) {
        gap.actual_value = gap.actual_sustained_solves_per_day;
        gap.delta_value =
            gap.actual_value - objective.requested_sustained_solves_per_day;
        gap.delta_pct =
            objective.requested_sustained_solves_per_day > 0.0
                ? (gap.delta_value / objective.requested_sustained_solves_per_day) * 100.0
                : 0.0;
    } else {
        gap.actual_value = gap.actual_mean_seconds_between_solves;
        gap.delta_value =
            gap.actual_value - objective.requested_mean_seconds_between_solves;
        gap.delta_pct =
            objective.requested_mean_seconds_between_solves > 0.0
                ? (gap.delta_value / objective.requested_mean_seconds_between_solves) * 100.0
                : 0.0;
    }
    return gap;
}

static UniValue BuildMatMulServiceDirectIssueDefaults(
    double target_solve_time_s,
    double validation_overhead_s,
    double propagation_overhead_s,
    const MatMulServiceDifficultyResolution& resolution,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    UniValue issue_defaults(UniValue::VOBJ);
    issue_defaults.pushKV("rpc", MATMUL_SERVICE_CHALLENGE_RPC);
    issue_defaults.pushKV("target_solve_time_s", target_solve_time_s);
    issue_defaults.pushKV("resolved_target_solve_time_s", resolution.resolved_solve_time_s);
    issue_defaults.pushKV("validation_overhead_s", validation_overhead_s);
    issue_defaults.pushKV("propagation_overhead_s", propagation_overhead_s);
    issue_defaults.pushKV("difficulty_policy", resolution.mode);
    issue_defaults.pushKV("difficulty_window_blocks", resolution.window_blocks);
    issue_defaults.pushKV("min_solve_time_s", resolution.min_solve_time_s);
    issue_defaults.pushKV("max_solve_time_s", resolution.max_solve_time_s);
    issue_defaults.pushKV("solver_parallelism", solver_parallelism);
    issue_defaults.pushKV("solver_duty_cycle_pct", solver_duty_cycle_pct);
    return issue_defaults;
}

static UniValue BuildMatMulServiceProfileIssueDefaults(
    const MatMulServiceDifficultyRecommendation& recommendation,
    const MatMulServiceDifficultyResolution& resolution,
    double validation_overhead_s,
    double propagation_overhead_s,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    UniValue profile_issue_defaults(UniValue::VOBJ);
    profile_issue_defaults.pushKV("rpc", MATMUL_SERVICE_CHALLENGE_PROFILE_ISSUE_RPC);
    profile_issue_defaults.pushKV("profile_name", recommendation.profile_name);
    profile_issue_defaults.pushKV("difficulty_label", recommendation.difficulty_label);
    profile_issue_defaults.pushKV("resolved_target_solve_time_s", resolution.resolved_solve_time_s);
    profile_issue_defaults.pushKV("validation_overhead_s", validation_overhead_s);
    profile_issue_defaults.pushKV("propagation_overhead_s", propagation_overhead_s);
    profile_issue_defaults.pushKV("min_solve_time_s", resolution.min_solve_time_s);
    profile_issue_defaults.pushKV("max_solve_time_s", resolution.max_solve_time_s);
    profile_issue_defaults.pushKV("solve_time_multiplier", recommendation.solve_time_multiplier);
    profile_issue_defaults.pushKV("difficulty_policy", resolution.mode);
    profile_issue_defaults.pushKV("difficulty_window_blocks", resolution.window_blocks);
    profile_issue_defaults.pushKV("solver_parallelism", solver_parallelism);
    profile_issue_defaults.pushKV("solver_duty_cycle_pct", solver_duty_cycle_pct);
    return profile_issue_defaults;
}

static UniValue BuildMatMulOperatorCapacityPlan(
    double total_target_s,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    const auto plan = ResolveMatMulOperatorCapacityPlan(
        total_target_s,
        solver_parallelism,
        solver_duty_cycle_pct);
    UniValue result(UniValue::VOBJ);
    result.pushKV("estimation_basis", plan.estimation_basis);
    result.pushKV("solver_parallelism", plan.solver_parallelism);
    result.pushKV("solver_duty_cycle_pct", plan.solver_duty_cycle_pct);
    result.pushKV("effective_parallelism", plan.effective_parallelism);
    result.pushKV(
        "budgeted_solver_seconds_per_hour",
        plan.budgeted_solver_seconds_per_hour);
    result.pushKV(
        "estimated_sustained_solves_per_hour",
        plan.estimated_sustained_solves_per_hour);
    result.pushKV(
        "estimated_sustained_solves_per_day",
        plan.estimated_sustained_solves_per_day);
    result.pushKV(
        "estimated_mean_seconds_between_solves",
        plan.estimated_mean_seconds_between_solves);
    return result;
}

static UniValue BuildMatMulServiceDifficultyRecommendation(
    const MatMulServiceDifficultyRecommendation& recommendation,
    const MatMulServiceDifficultyResolution& resolution,
    double validation_overhead_s,
    double propagation_overhead_s,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    const double estimated_average_node_total_time_s =
        resolution.resolved_solve_time_s + validation_overhead_s + propagation_overhead_s;
    UniValue result(UniValue::VOBJ);
    result.pushKV("name", recommendation.profile_name);
    result.pushKV("difficulty_label", recommendation.difficulty_label);
    result.pushKV("effort_tier", recommendation.effort_tier);
    result.pushKV("description", recommendation.description);
    result.pushKV("network_target_s", recommendation.network_target_s);
    result.pushKV("network_target_ratio", recommendation.solve_time_ratio);
    result.pushKV("solve_time_multiplier", recommendation.solve_time_multiplier);
    result.pushKV("unclamped_target_solve_time_s", recommendation.unclamped_solve_time_s);
    result.pushKV("recommended_target_solve_time_s", recommendation.recommended_solve_time_s);
    result.pushKV("resolved_target_solve_time_s", resolution.resolved_solve_time_s);
    result.pushKV("min_solve_time_s", recommendation.min_solve_time_s);
    result.pushKV("max_solve_time_s", recommendation.max_solve_time_s);
    result.pushKV("clamped", recommendation.clamped);
    result.pushKV("estimated_average_node_solve_time_s", resolution.resolved_solve_time_s);
    result.pushKV("estimated_average_node_total_time_s", estimated_average_node_total_time_s);
    result.pushKV(
        "estimated_average_node_challenges_per_hour",
        estimated_average_node_total_time_s > 0.0 ? 3600.0 / estimated_average_node_total_time_s : 0.0);
    result.pushKV(
        "operator_capacity",
        BuildMatMulOperatorCapacityPlan(
            estimated_average_node_total_time_s,
            solver_parallelism,
            solver_duty_cycle_pct));
    result.pushKV(
        "difficulty_resolution",
        BuildMatMulServiceDifficultyResolution(resolution));
    UniValue issue_defaults = BuildMatMulServiceDirectIssueDefaults(
        recommendation.recommended_solve_time_s,
        validation_overhead_s,
        propagation_overhead_s,
        resolution,
        solver_parallelism,
        solver_duty_cycle_pct);
    issue_defaults.pushKV("profile_name", recommendation.profile_name);
    issue_defaults.pushKV("difficulty_label", recommendation.difficulty_label);
    result.pushKV("issue_defaults", std::move(issue_defaults));
    result.pushKV(
        "profile_issue_defaults",
        BuildMatMulServiceProfileIssueDefaults(
            recommendation,
            resolution,
            validation_overhead_s,
            propagation_overhead_s,
            solver_parallelism,
            solver_duty_cycle_pct));
    return result;
}

static UniValue BuildMatMulServiceDifficultyResolution(
    const MatMulServiceDifficultyResolution& resolution)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("mode", resolution.mode);
    result.pushKV("base_solve_time_s", resolution.base_solve_time_s);
    result.pushKV("adjusted_solve_time_s", resolution.adjusted_solve_time_s);
    result.pushKV("resolved_solve_time_s", resolution.resolved_solve_time_s);
    result.pushKV("min_solve_time_s", resolution.min_solve_time_s);
    result.pushKV("max_solve_time_s", resolution.max_solve_time_s);
    result.pushKV("window_blocks", resolution.window_blocks);
    result.pushKV(
        "observed_interval_count",
        static_cast<uint64_t>(resolution.observed_interval_count));
    result.pushKV("observed_mean_interval_s", resolution.observed_mean_interval_s);
    result.pushKV("network_target_s", resolution.network_target_s);
    result.pushKV("interval_scale", resolution.interval_scale);
    result.pushKV("clamped", resolution.clamped);
    return result;
}

struct MatMulServiceChallengeRegistryEntry {
    int64_t issued_at{0};
    int64_t expires_at{0};
    bool redeemed{false};
    int64_t redeemed_at{0};

    SERIALIZE_METHODS(MatMulServiceChallengeRegistryEntry, obj)
    {
        READWRITE(obj.issued_at, obj.expires_at, obj.redeemed, obj.redeemed_at);
    }
};

struct MatMulServiceChallengeRegistryStatus {
    bool local_registry_status_checked{true};
    bool issued_by_local_node{false};
    bool redeemed{false};
    bool redeemable{false};
    int64_t redeemed_at{0};
    bool redeemed_now{false};
};

struct MatMulServiceChallengeRegistryHealth {
    std::string status{MATMUL_SERVICE_REGISTRY_STATUS_NOT_LOADED};
    std::string path;
    std::string quarantine_path;
    std::string error;
    bool healthy{true};
    bool shared{false};
    int64_t last_checked_at{0};
    int64_t last_success_at{0};
    int64_t last_failure_at{0};
    uint64_t entries{0};
};

struct MatMulServiceProofBatchItem {
    UniValue challenge;
    std::string nonce64_hex;
    std::string digest_hex;
};

static Mutex g_matmul_service_challenge_registry_mutex;
static std::map<uint256, MatMulServiceChallengeRegistryEntry>
    g_matmul_service_challenge_registry GUARDED_BY(g_matmul_service_challenge_registry_mutex);
static MatMulServiceChallengeRegistryHealth
    g_matmul_service_challenge_registry_health GUARDED_BY(g_matmul_service_challenge_registry_mutex);

static bool MatMulServiceChallengeRegistryIsShared(const ArgsManager& args)
{
    return args.IsArgSet("-matmulservicechallengefile");
}

static const char* GetMatMulServiceChallengeRegistryStoreLabel(const ArgsManager& args)
{
    return MatMulServiceChallengeRegistryIsShared(args)
        ? MATMUL_SERVICE_ISSUED_STORE_SHARED_FILE_LOCK_STORE
        : MATMUL_SERVICE_ISSUED_STORE_LOCAL_PERSISTENT_FILE;
}

static const char* GetMatMulServiceChallengeRegistryScope(const ArgsManager& args)
{
    return MatMulServiceChallengeRegistryIsShared(args)
        ? MATMUL_SERVICE_ISSUED_SCOPE_SHARED_FILE
        : MATMUL_SERVICE_ISSUED_SCOPE_NODE_LOCAL;
}

static fs::path GetMatMulServiceChallengeRegistryPath(const ArgsManager& args)
{
    if (args.IsArgSet("-matmulservicechallengefile")) {
        const fs::path configured = args.GetPathArg("-matmulservicechallengefile");
        return configured.is_absolute() ? configured : fsbridge::AbsPathJoin(args.GetDataDirNet(), configured);
    }
    return args.GetDataDirNet() / MATMUL_SERVICE_REGISTRY_FILENAME;
}

static fs::path GetMatMulServiceChallengeRegistryLockPath(const ArgsManager& args)
{
    fs::path lock_path = GetMatMulServiceChallengeRegistryPath(args);
    lock_path += ".lock";
    return lock_path;
}

static void UpdateMatMulServiceChallengeRegistryHealthLocked(
    const ArgsManager& args,
    std::string status,
    bool healthy,
    int64_t now,
    std::string error = {},
    std::string quarantine_path = {})
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    g_matmul_service_challenge_registry_health.status = std::move(status);
    g_matmul_service_challenge_registry_health.path =
        fs::PathToString(GetMatMulServiceChallengeRegistryPath(args));
    g_matmul_service_challenge_registry_health.quarantine_path = std::move(quarantine_path);
    g_matmul_service_challenge_registry_health.error = std::move(error);
    g_matmul_service_challenge_registry_health.healthy = healthy;
    g_matmul_service_challenge_registry_health.shared = MatMulServiceChallengeRegistryIsShared(args);
    g_matmul_service_challenge_registry_health.last_checked_at = now;
    g_matmul_service_challenge_registry_health.entries =
        static_cast<uint64_t>(g_matmul_service_challenge_registry.size());
    if (healthy) {
        g_matmul_service_challenge_registry_health.last_success_at = now;
    } else {
        g_matmul_service_challenge_registry_health.last_failure_at = now;
    }
}

static fs::path BuildMatMulServiceChallengeRegistryQuarantinePath(
    const fs::path& path,
    const char* reason,
    int64_t now)
{
    fs::path quarantine_path = path;
    quarantine_path += strprintf(".%s.%lld.quarantine", reason, static_cast<long long>(now));
    return quarantine_path;
}

static bool QuarantineMatMulServiceChallengeRegistryFile(
    const fs::path& path,
    const char* reason,
    int64_t now,
    fs::path& quarantine_path)
{
    quarantine_path = BuildMatMulServiceChallengeRegistryQuarantinePath(path, reason, now);
    return RenameOver(path, quarantine_path);
}

static MatMulServiceChallengeRegistryHealth GetMatMulServiceChallengeRegistryHealthSnapshot(
    const ArgsManager& args) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(g_matmul_service_challenge_registry_mutex);
    MatMulServiceChallengeRegistryHealth health = g_matmul_service_challenge_registry_health;
    if (health.path.empty()) {
        health.path = fs::PathToString(GetMatMulServiceChallengeRegistryPath(args));
        health.shared = MatMulServiceChallengeRegistryIsShared(args);
    }
    return health;
}

static UniValue MatMulServiceChallengeRegistryHealthToUniValue(
    const MatMulServiceChallengeRegistryHealth& health)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("status", health.status);
    obj.pushKV("healthy", health.healthy);
    obj.pushKV("shared", health.shared);
    obj.pushKV("path", health.path);
    obj.pushKV("entries", health.entries);
    obj.pushKV("last_checked_at", health.last_checked_at);
    if (health.last_success_at > 0) {
        obj.pushKV("last_success_at", health.last_success_at);
    }
    if (health.last_failure_at > 0) {
        obj.pushKV("last_failure_at", health.last_failure_at);
    }
    if (!health.quarantine_path.empty()) {
        obj.pushKV("quarantine_path", health.quarantine_path);
    }
    if (!health.error.empty()) {
        obj.pushKV("error", health.error);
    }
    return obj;
}

static std::unique_ptr<fsbridge::FileLock> AcquireMatMulServiceChallengeRegistryFileLock(const ArgsManager& args)
{
    const fs::path lock_path = GetMatMulServiceChallengeRegistryLockPath(args);
    if (!lock_path.parent_path().empty() && !TryCreateDirectories(lock_path.parent_path()) && !fs::exists(lock_path.parent_path())) {
        throw std::runtime_error(
            strprintf(
                "Failed to create challenge registry lock directory %s",
                fs::PathToString(lock_path.parent_path())));
    }
    if (AutoFile lock_file{fsbridge::fopen(lock_path, "ab")}; !lock_file.IsNull()) {
        if (lock_file.fclose() != 0) {
            throw std::runtime_error(
                strprintf("Error closing %s: %s", fs::PathToString(lock_path), SysErrorString(errno)));
        }
    } else {
        throw std::runtime_error(
            strprintf("Failed to create challenge registry lock file %s", fs::PathToString(lock_path)));
    }

    auto lock = std::make_unique<fsbridge::FileLock>(lock_path);
    for (size_t attempt = 0; attempt < MATMUL_SERVICE_REGISTRY_LOCK_ATTEMPTS; ++attempt) {
        if (lock->TryLock()) {
            return lock;
        }
        std::this_thread::sleep_for(MATMUL_SERVICE_REGISTRY_LOCK_WAIT);
    }
    throw std::runtime_error(
        strprintf(
            "Failed to lock challenge registry %s after %u attempts: %s",
            fs::PathToString(lock_path),
            static_cast<unsigned>(MATMUL_SERVICE_REGISTRY_LOCK_ATTEMPTS),
            lock->GetReason()));
}

static void LoadMatMulServiceChallengeRegistryLocked(const ArgsManager& args, const fs::path& path)
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    g_matmul_service_challenge_registry.clear();
    const int64_t now = GetTime();

    AutoFile file{fsbridge::fopen(path, "rb")};
    if (file.IsNull()) {
        if (g_matmul_service_challenge_registry_health.last_failure_at == 0 ||
            g_matmul_service_challenge_registry_health.healthy) {
            UpdateMatMulServiceChallengeRegistryHealthLocked(
                args,
                MATMUL_SERVICE_REGISTRY_STATUS_MISSING,
                true,
                now);
        }
        return;
    }

    try {
        uint64_t version{0};
        file >> version;
        if (version != MATMUL_SERVICE_REGISTRY_DISK_VERSION) {
            fs::path quarantine_path;
            const bool quarantined = QuarantineMatMulServiceChallengeRegistryFile(
                path,
                "unsupported-version",
                now,
                quarantine_path);
            LogPrintf(
                "[matmul_service] %s challenge registry %s with unsupported version %u (%s)\n",
                quarantined ? "quarantined" : "failed to quarantine",
                fs::PathToString(path),
                version,
                quarantined ? fs::PathToString(quarantine_path) : "rename failed");
            g_matmul_service_challenge_registry.clear();
            UpdateMatMulServiceChallengeRegistryHealthLocked(
                args,
                quarantined ? MATMUL_SERVICE_REGISTRY_STATUS_UNSUPPORTED_VERSION_QUARANTINED
                            : MATMUL_SERVICE_REGISTRY_STATUS_QUARANTINE_FAILED,
                false,
                now,
                strprintf("unsupported registry version %u", version),
                quarantined ? fs::PathToString(quarantine_path) : "");
            return;
        }
        file >> g_matmul_service_challenge_registry;
        UpdateMatMulServiceChallengeRegistryHealthLocked(
            args,
            MATMUL_SERVICE_REGISTRY_STATUS_OK,
            true,
            now);
    } catch (const std::exception& e) {
        fs::path quarantine_path;
        const bool quarantined = QuarantineMatMulServiceChallengeRegistryFile(
            path,
            "corrupt",
            now,
            quarantine_path);
        LogPrintf(
            "[matmul_service] %s challenge registry %s after load failure: %s (%s)\n",
            quarantined ? "quarantined" : "failed to quarantine",
            fs::PathToString(path),
            e.what(),
            quarantined ? fs::PathToString(quarantine_path) : "rename failed");
        g_matmul_service_challenge_registry.clear();
        UpdateMatMulServiceChallengeRegistryHealthLocked(
            args,
            quarantined ? MATMUL_SERVICE_REGISTRY_STATUS_CORRUPT_QUARANTINED
                        : MATMUL_SERVICE_REGISTRY_STATUS_QUARANTINE_FAILED,
            false,
            now,
            e.what(),
            quarantined ? fs::PathToString(quarantine_path) : "");
    }
}

static bool PersistMatMulServiceChallengeRegistryLocked(const ArgsManager& args, const fs::path& path)
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    fs::path tmppath = path;
    tmppath += ".new";

    AutoFile file{fsbridge::fopen(tmppath, "wb")};
    if (file.IsNull()) {
        LogPrintf(
            "[matmul_service] failed to open challenge registry %s for writing\n",
            fs::PathToString(tmppath));
        return false;
    }

    try {
        file << MATMUL_SERVICE_REGISTRY_DISK_VERSION;
        file << g_matmul_service_challenge_registry;
        if (!file.Commit()) {
            throw std::runtime_error("Commit failed");
        }
        if (file.fclose() != 0) {
            throw std::runtime_error(
                strprintf("Error closing %s: %s", fs::PathToString(tmppath), SysErrorString(errno)));
        }
        if (!RenameOver(tmppath, path)) {
            throw std::runtime_error("Rename failed");
        }
        UpdateMatMulServiceChallengeRegistryHealthLocked(
            args,
            MATMUL_SERVICE_REGISTRY_STATUS_OK,
            true,
            GetTime());
        return true;
    } catch (const std::exception& e) {
        LogPrintf(
            "[matmul_service] failed to persist challenge registry %s: %s\n",
            fs::PathToString(path),
            e.what());
        (void)file.fclose();
        fs::remove(tmppath);
        UpdateMatMulServiceChallengeRegistryHealthLocked(
            args,
            MATMUL_SERVICE_REGISTRY_STATUS_QUARANTINE_FAILED,
            false,
            GetTime(),
            e.what());
        return false;
    }
}

static void PersistMatMulServiceChallengeRegistryOrThrowLocked(
    const ArgsManager& args,
    const fs::path& path,
    const char* action)
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    if (!PersistMatMulServiceChallengeRegistryLocked(args, path)) {
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            strprintf(
                "Failed to persist MatMul service challenge registry while %s (%s)",
                action,
                fs::PathToString(path)));
    }
}

static bool PruneMatMulServiceChallengeRegistry(int64_t now)
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    bool changed{false};
    for (auto it = g_matmul_service_challenge_registry.begin(); it != g_matmul_service_challenge_registry.end();) {
        if (it->second.expires_at < now) {
            it = g_matmul_service_challenge_registry.erase(it);
            changed = true;
        } else {
            ++it;
        }
    }

    while (g_matmul_service_challenge_registry.size() > MATMUL_SERVICE_ISSUED_CACHE_CAPACITY) {
        auto oldest = g_matmul_service_challenge_registry.begin();
        for (auto it = std::next(g_matmul_service_challenge_registry.begin());
             it != g_matmul_service_challenge_registry.end();
             ++it) {
            if (it->second.issued_at < oldest->second.issued_at) {
                oldest = it;
            }
        }
        g_matmul_service_challenge_registry.erase(oldest);
        changed = true;
    }
    return changed;
}

static void RememberIssuedMatMulServiceChallengeLocked(
    const ArgsManager& args,
    const uint256& challenge_id,
    int64_t issued_at,
    int64_t expires_at)
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    const fs::path path = GetMatMulServiceChallengeRegistryPath(args);
    const auto file_lock = AcquireMatMulServiceChallengeRegistryFileLock(args);
    LoadMatMulServiceChallengeRegistryLocked(args, path);
    (void)PruneMatMulServiceChallengeRegistry(issued_at);
    g_matmul_service_challenge_registry[challenge_id] =
        MatMulServiceChallengeRegistryEntry{issued_at, expires_at, false, 0};
    PersistMatMulServiceChallengeRegistryOrThrowLocked(args, path, "issuing a challenge");
}

static void RememberIssuedMatMulServiceChallenge(
    const ArgsManager& args,
    const uint256& challenge_id,
    int64_t issued_at,
    int64_t expires_at) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(g_matmul_service_challenge_registry_mutex);
    RememberIssuedMatMulServiceChallengeLocked(args, challenge_id, issued_at, expires_at);
}

static MatMulServiceChallengeRegistryStatus GetMatMulServiceChallengeRegistryStatusLocked(
    const ArgsManager& args,
    const uint256& challenge_id,
    int64_t now,
    int64_t expires_at)
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    const fs::path path = GetMatMulServiceChallengeRegistryPath(args);
    const auto file_lock = AcquireMatMulServiceChallengeRegistryFileLock(args);
    LoadMatMulServiceChallengeRegistryLocked(args, path);
    const bool pruned = PruneMatMulServiceChallengeRegistry(now);
    if (pruned) {
        PersistMatMulServiceChallengeRegistryOrThrowLocked(args, path, "pruning expired challenges");
    }

    MatMulServiceChallengeRegistryStatus status;
    const auto it = g_matmul_service_challenge_registry.find(challenge_id);
    if (it == g_matmul_service_challenge_registry.end()) {
        return status;
    }

    status.issued_by_local_node = true;
    status.redeemed = it->second.redeemed;
    status.redeemed_at = it->second.redeemed_at;
    status.redeemable = !status.redeemed && expires_at >= now;
    return status;
}

static MatMulServiceChallengeRegistryStatus GetMatMulServiceChallengeRegistryStatus(
    const ArgsManager& args,
    const uint256& challenge_id,
    int64_t now,
    int64_t expires_at) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(g_matmul_service_challenge_registry_mutex);
    return GetMatMulServiceChallengeRegistryStatusLocked(args, challenge_id, now, expires_at);
}

static MatMulServiceChallengeRegistryStatus RedeemMatMulServiceChallengeLocked(
    const ArgsManager& args,
    const uint256& challenge_id,
    int64_t now,
    int64_t expires_at)
    EXCLUSIVE_LOCKS_REQUIRED(g_matmul_service_challenge_registry_mutex)
{
    const fs::path path = GetMatMulServiceChallengeRegistryPath(args);
    const auto file_lock = AcquireMatMulServiceChallengeRegistryFileLock(args);
    LoadMatMulServiceChallengeRegistryLocked(args, path);
    const bool pruned = PruneMatMulServiceChallengeRegistry(now);

    MatMulServiceChallengeRegistryStatus status;
    const auto it = g_matmul_service_challenge_registry.find(challenge_id);
    if (it == g_matmul_service_challenge_registry.end()) {
        if (pruned) {
            PersistMatMulServiceChallengeRegistryOrThrowLocked(args, path, "pruning expired challenges");
        }
        return status;
    }

    status.issued_by_local_node = true;
    if (it->second.redeemed) {
        status.redeemed = true;
        status.redeemed_at = it->second.redeemed_at;
        if (pruned) {
            PersistMatMulServiceChallengeRegistryOrThrowLocked(args, path, "pruning expired challenges");
        }
        return status;
    }
    if (expires_at < now) {
        if (pruned) {
            PersistMatMulServiceChallengeRegistryOrThrowLocked(args, path, "pruning expired challenges");
        }
        return status;
    }

    it->second.redeemed = true;
    it->second.redeemed_at = now;
    PersistMatMulServiceChallengeRegistryOrThrowLocked(args, path, "redeeming a challenge");
    status.redeemed = true;
    status.redeemed_at = now;
    status.redeemed_now = true;
    return status;
}

static MatMulServiceChallengeRegistryStatus RedeemMatMulServiceChallenge(
    const ArgsManager& args,
    const uint256& challenge_id,
    int64_t now,
    int64_t expires_at) NO_THREAD_SAFETY_ANALYSIS
{
    LOCK(g_matmul_service_challenge_registry_mutex);
    return RedeemMatMulServiceChallengeLocked(args, challenge_id, now, expires_at);
}

static void AppendMatMulServiceRegistryStatus(
    UniValue& result,
    const MatMulServiceChallengeRegistryStatus& status)
{
    result.pushKV("local_registry_status_checked", status.local_registry_status_checked);
    if (!status.local_registry_status_checked) {
        return;
    }
    result.pushKV("issued_by_local_node", status.issued_by_local_node);
    result.pushKV("redeemed", status.redeemed);
    result.pushKV("redeemable", status.redeemable);
    if (status.redeemed_at > 0) {
        result.pushKV("redeemed_at", status.redeemed_at);
    }
}

static std::vector<MatMulServiceProofBatchItem> ParseMatMulServiceProofBatchItems(const UniValue& batch_value)
{
    const UniValue& batch = batch_value.get_array();
    if (batch.empty() || batch.size() > MATMUL_SERVICE_MAX_BATCH_SIZE) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf(
                "proofs must contain between 1 and %u entries",
                static_cast<unsigned>(MATMUL_SERVICE_MAX_BATCH_SIZE)));
    }

    std::vector<MatMulServiceProofBatchItem> items;
    items.reserve(batch.size());
    for (size_t index = 0; index < batch.size(); ++index) {
        try {
            const UniValue& entry = batch[index].get_obj();
            const UniValue& challenge = entry.find_value("challenge");
            const UniValue& nonce64_hex = entry.find_value("nonce64_hex");
            const UniValue& digest_hex = entry.find_value("digest_hex");
            if (challenge.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "challenge is required");
            }
            if (nonce64_hex.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "nonce64_hex is required");
            }
            if (!nonce64_hex.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "nonce64_hex must be a string");
            }
            if (digest_hex.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "digest_hex is required");
            }
            if (!digest_hex.isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "digest_hex must be a string");
            }

            MatMulServiceProofBatchItem item;
            item.challenge = challenge;
            item.nonce64_hex = nonce64_hex.get_str();
            item.digest_hex = digest_hex.get_str();
            items.push_back(std::move(item));
        } catch (const UniValue& obj_error) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "proofs[%u].%s",
                    static_cast<unsigned>(index),
                    obj_error.find_value("message").get_str()));
        } catch (const std::exception& e) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("proofs[%u].%s", static_cast<unsigned>(index), e.what()));
        }
    }

    return items;
}

static uint256 HashMatMulServiceText(std::string_view label, std::string_view value)
{
    HashWriter hw;
    hw << std::string{MATMUL_SERVICE_DOMAIN} << std::string{label} << std::string{value};
    return hw.GetSHA256();
}

static uint256 ComputeMatMulServiceBindingHash(
    std::string_view chain,
    std::string_view purpose,
    const uint256& resource_hash,
    const uint256& subject_hash)
{
    HashWriter hw;
    hw << std::string{MATMUL_SERVICE_DOMAIN} << std::string{"binding"} << std::string{chain}
       << std::string{purpose} << resource_hash << subject_hash;
    return hw.GetSHA256();
}

static uint256 ComputeMatMulServiceChallengeId(
    std::string_view chain,
    const uint256& binding_hash,
    const uint256& salt,
    const uint256& anchor_hash,
    int anchor_height,
    int64_t issued_at,
    int64_t expires_at,
    int64_t target_solve_time_ms,
    int64_t validation_overhead_ms,
    int64_t propagation_overhead_ms)
{
    HashWriter hw;
    hw << std::string{MATMUL_SERVICE_DOMAIN} << std::string{"challenge"} << std::string{chain}
       << binding_hash << salt << anchor_hash << anchor_height << issued_at << expires_at
       << target_solve_time_ms << validation_overhead_ms << propagation_overhead_ms;
    return hw.GetSHA256();
}

static uint256 DeriveMatMulServiceSeed(
    const uint256& challenge_id,
    const uint256& anchor_hash,
    std::string_view label)
{
    HashWriter hw;
    hw << std::string{MATMUL_SERVICE_DOMAIN} << std::string{label} << challenge_id << anchor_hash;
    return hw.GetSHA256();
}

static uint256 DeriveMatMulServiceMerkleRoot(
    const uint256& challenge_id,
    const uint256& binding_hash)
{
    HashWriter hw;
    hw << std::string{MATMUL_SERVICE_DOMAIN} << std::string{"merkle"} << challenge_id << binding_hash;
    return hw.GetSHA256();
}

static void ValidateMatMulServiceText(std::string_view value, const char* field_name)
{
    if (value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be non-empty", field_name));
    }
    if (value.size() > MATMUL_SERVICE_MAX_TEXT_BYTES) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s must be at most %u bytes", field_name, static_cast<unsigned>(MATMUL_SERVICE_MAX_TEXT_BYTES)));
    }
}

static bool ParseNonce64Hex(std::string_view nonce64_hex, uint64_t& out)
{
    if (nonce64_hex.size() != 16 || !IsHex(nonce64_hex)) return false;
    const auto bytes = TryParseHex<uint8_t>(nonce64_hex);
    if (!bytes.has_value() || bytes->size() != 8) return false;
    out = 0;
    for (uint8_t byte : *bytes) {
        out = (out << 8) | byte;
    }
    return true;
}

static uint256 ParseUint256HexOrThrow(std::string_view hex, const char* message)
{
    const auto parsed = uint256::FromHex(hex);
    if (!parsed.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, message);
    }
    return *parsed;
}

static double ParseNumericServiceField(const UniValue& value, const char* field_name)
{
    if (value.isNum()) {
        return value.get_real();
    }
    if (value.isStr()) {
        try {
            size_t parsed_chars{0};
            const double out = std::stod(value.get_str(), &parsed_chars);
            if (parsed_chars != value.get_str().size()) {
                throw std::invalid_argument("trailing characters");
            }
            return out;
        } catch (const std::exception&) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("invalid service challenge: %s must be numeric", field_name));
        }
    }
    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf("invalid service challenge: %s must be numeric", field_name));
}

template <typename Int>
static Int ParseIntegralServiceField(const UniValue& value, const char* field_name)
{
    static_assert(std::is_integral_v<Int>);
    if (value.isNum()) {
        return value.getInt<Int>();
    }
    if (value.isStr()) {
        Int out{0};
        const std::string& text = value.get_str();
        const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
        if (ec == std::errc{} && ptr == text.data() + text.size()) {
            return out;
        }
    }
    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf("invalid service challenge: %s must be an integer", field_name));
}

static UniValue BuildMatMulServiceProofPolicy(const ArgsManager& args)
{
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("verification_rule", MATMUL_SERVICE_VERIFICATION_RULE);
    policy.pushKV("sigma_gate_applied", false);
    policy.pushKV("expiration_enforced", true);
    policy.pushKV("challenge_id_required", true);
    policy.pushKV("replay_protection", MATMUL_SERVICE_REDEEM_RPC);
    policy.pushKV("redeem_rpc", MATMUL_SERVICE_REDEEM_RPC);
    policy.pushKV("solve_rpc", MATMUL_SERVICE_SOLVE_RPC);
    policy.pushKV("locally_issued_required", true);
    policy.pushKV("issued_challenge_store", GetMatMulServiceChallengeRegistryStoreLabel(args));
    policy.pushKV("issued_challenge_scope", GetMatMulServiceChallengeRegistryScope(args));
    return policy;
}

static arith_uint256 ComputeExpectedMatMulServiceTarget(
    ChainstateManager& chainman,
    const uint256& anchor_hash,
    int anchor_height,
    int64_t issued_at,
    int64_t target_solve_time_ms);

static UniValue BuildMatMulServiceChallengeResponse(
    ChainstateManager& chainman,
    const NodeContext& node,
    std::string purpose,
    std::string resource,
    std::string subject,
    double solve_time_target_s,
    int64_t expires_in_s,
    double validation_overhead_s,
    double propagation_overhead_s,
    std::string_view difficulty_policy,
    int difficulty_window_blocks,
    double min_solve_time_s,
    double max_solve_time_s,
    int solver_parallelism = MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM,
    double solver_duty_cycle_pct = MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT)
{
    ValidateMatMulServiceText(purpose, "purpose");
    ValidateMatMulServiceText(resource, "resource");
    ValidateMatMulServiceText(subject, "subject");

    const ArgsManager& args = EnsureArgsman(node);
    const std::string chain_name = chainman.GetParams().GetChainTypeString();
    const Consensus::Params& consensus = chainman.GetConsensus();
    Mining& miner = EnsureMining(node);
    std::unique_ptr<BlockTemplate> block_template = miner.createNewBlock();
    CHECK_NONFATAL(block_template);

    CBlockHeader template_header{block_template->getBlockHeader()};
    const CBlockIndex* pindex_prev{nullptr};
    int next_height{0};
    {
        LOCK(cs_main);
        pindex_prev = chainman.m_blockman.LookupBlockIndex(template_header.hashPrevBlock);
        CHECK_NONFATAL(pindex_prev != nullptr);
        if (!TryGetNextBlockHeight(pindex_prev, next_height)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "next block height overflow");
        }
    }

    const auto difficulty_resolution = ResolveMatMulServiceDifficultyPolicy(
        consensus,
        pindex_prev,
        difficulty_policy,
        solve_time_target_s,
        difficulty_window_blocks,
        min_solve_time_s,
        max_solve_time_s);

    const uint256 resource_hash = HashMatMulServiceText("resource", resource);
    const uint256 subject_hash = HashMatMulServiceText("subject", subject);
    const uint256 binding_hash = ComputeMatMulServiceBindingHash(chain_name, purpose, resource_hash, subject_hash);
    const uint256 salt = GetRandHash();
    const int64_t issued_at = GetTime();
    const int64_t expires_at = issued_at + expires_in_s;
    const int64_t target_solve_time_ms = static_cast<int64_t>(std::llround(
        difficulty_resolution.resolved_solve_time_s * 1000.0));
    const int64_t validation_overhead_ms = static_cast<int64_t>(std::llround(validation_overhead_s * 1000.0));
    const int64_t propagation_overhead_ms = static_cast<int64_t>(std::llround(propagation_overhead_s * 1000.0));
    const uint256 challenge_id = ComputeMatMulServiceChallengeId(
        chain_name,
        binding_hash,
        salt,
        template_header.hashPrevBlock,
        next_height - 1,
        issued_at,
        expires_at,
        target_solve_time_ms,
        validation_overhead_ms,
        propagation_overhead_ms);

    CBlockHeader challenge_header;
    challenge_header.nVersion = template_header.nVersion;
    challenge_header.hashPrevBlock = template_header.hashPrevBlock;
    challenge_header.hashMerkleRoot = DeriveMatMulServiceMerkleRoot(challenge_id, binding_hash);
    challenge_header.nTime = static_cast<uint32_t>(issued_at);
    challenge_header.nNonce64 = 0;
    challenge_header.nNonce = 0;
    challenge_header.mix_hash.SetNull();
    challenge_header.matmul_digest.SetNull();
    challenge_header.matmul_dim =
        template_header.matmul_dim == 0 ? static_cast<uint16_t>(consensus.nMatMulDimension) : template_header.matmul_dim;
    challenge_header.seed_a = DeriveMatMulServiceSeed(challenge_id, challenge_header.hashPrevBlock, "seed_a");
    challenge_header.seed_b = DeriveMatMulServiceSeed(challenge_id, challenge_header.hashPrevBlock, "seed_b");

    const arith_uint256 profiled_target = ComputeExpectedMatMulServiceTarget(
        chainman,
        challenge_header.hashPrevBlock,
        next_height - 1,
        issued_at,
        target_solve_time_ms);
    challenge_header.nBits = profiled_target.GetCompact();

    CBlockIndex profiled_index;
    profiled_index.pprev = const_cast<CBlockIndex*>(pindex_prev);
    profiled_index.nHeight = next_height;
    profiled_index.nTime = challenge_header.nTime;
    profiled_index.nBits = challenge_header.nBits;

    MatMulWorkProfileOptions work_profile_options;
    work_profile_options.seed_derivation_scope = "per_service_challenge";
    work_profile_options.seed_derivation_rule = MATMUL_SERVICE_SEED_DERIVATION_RULE;
    work_profile_options.winner_knows_next_seeds_first = false;
    work_profile_options.publicly_precomputable_before_parent_seen = false;
    work_profile_options.public_precompute_horizon_blocks = 0;
    work_profile_options.template_mutations_preserve_seed = {"nonce"};
    work_profile_options.sigma_gate_applied = false;
    work_profile_options.sigma_rule = "not_applied_to_service_proofs";
    work_profile_options.digest_rule = MATMUL_SERVICE_VERIFICATION_RULE;
    work_profile_options.pre_hash_epsilon_bits_override = 0;

    UniValue challenge(UniValue::VOBJ);
    challenge.pushKV("chain", chain_name);
    challenge.pushKV("algorithm", "matmul");
    challenge.pushKV("height", next_height);
    challenge.pushKV("previousblockhash", challenge_header.hashPrevBlock.GetHex());
    challenge.pushKV("mintime", issued_at);
    challenge.pushKV("bits", strprintf("%08x", challenge_header.nBits));
    challenge.pushKV("difficulty", GetDifficulty(profiled_index));
    challenge.pushKV("target", GetTarget(profiled_index, consensus.powLimit).GetHex());
    challenge.pushKV("noncerange", "0000000000000000ffffffffffffffff");

    UniValue header_context(UniValue::VOBJ);
    header_context.pushKV("version", challenge_header.nVersion);
    header_context.pushKV("previousblockhash", challenge_header.hashPrevBlock.GetHex());
    header_context.pushKV("merkleroot", challenge_header.hashMerkleRoot.GetHex());
    header_context.pushKV("time", challenge_header.GetBlockTime());
    header_context.pushKV("bits", strprintf("%08x", challenge_header.nBits));
    header_context.pushKV("nonce64_start", static_cast<uint64_t>(challenge_header.nNonce64));
    header_context.pushKV("matmul_dim", static_cast<uint64_t>(challenge_header.matmul_dim));
    header_context.pushKV("seed_a", challenge_header.seed_a.GetHex());
    header_context.pushKV("seed_b", challenge_header.seed_b.GetHex());
    challenge.pushKV("header_context", std::move(header_context));

    UniValue matmul(UniValue::VOBJ);
    matmul.pushKV("n", static_cast<uint64_t>(challenge_header.matmul_dim));
    matmul.pushKV("b", static_cast<uint64_t>(consensus.nMatMulTranscriptBlockSize));
    matmul.pushKV("r", static_cast<uint64_t>(consensus.nMatMulNoiseRank));
    matmul.pushKV("q", static_cast<uint64_t>(consensus.nMatMulFieldModulus));
    matmul.pushKV("min_dimension", static_cast<uint64_t>(consensus.nMatMulMinDimension));
    matmul.pushKV("max_dimension", static_cast<uint64_t>(consensus.nMatMulMaxDimension));
    matmul.pushKV("seed_a", challenge_header.seed_a.GetHex());
    matmul.pushKV("seed_b", challenge_header.seed_b.GetHex());
    challenge.pushKV("matmul", std::move(matmul));
    challenge.pushKV("work_profile", BuildMatMulWorkProfile(challenge_header, consensus, next_height, work_profile_options));
    {
        LOCK(cs_main);
        challenge.pushKV(
            "service_profile",
            BuildServiceProfile(
                chainman,
                node,
                static_cast<double>(consensus.nPowTargetSpacing),
                difficulty_resolution.resolved_solve_time_s,
                validation_overhead_s,
                propagation_overhead_s,
                &difficulty_resolution,
                solver_parallelism,
                solver_duty_cycle_pct));
    }

    UniValue binding(UniValue::VOBJ);
    binding.pushKV("chain", chain_name);
    binding.pushKV("purpose", purpose);
    binding.pushKV("resource", resource);
    binding.pushKV("subject", subject);
    binding.pushKV("resource_hash", resource_hash.GetHex());
    binding.pushKV("subject_hash", subject_hash.GetHex());
    binding.pushKV("salt", salt.GetHex());
    binding.pushKV("anchor_height", next_height - 1);
    binding.pushKV("anchor_hash", challenge_header.hashPrevBlock.GetHex());
    binding.pushKV("challenge_id_rule", MATMUL_SERVICE_CHALLENGE_ID_RULE);
    binding.pushKV("seed_derivation_rule", MATMUL_SERVICE_SEED_DERIVATION_RULE);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("kind", MATMUL_SERVICE_KIND);
    obj.pushKV("challenge_id", challenge_id.GetHex());
    obj.pushKV("issued_at", issued_at);
    obj.pushKV("expires_at", expires_at);
    obj.pushKV("expires_in_s", expires_in_s);
    obj.pushKV("binding", std::move(binding));
    obj.pushKV("proof_policy", BuildMatMulServiceProofPolicy(args));
    obj.pushKV("challenge", std::move(challenge));
    RememberIssuedMatMulServiceChallenge(args, challenge_id, issued_at, expires_at);
    return obj;
}

static UniValue BuildMatMulServiceChallengeProfileResponse(
    ChainstateManager& chainman,
    const NodeContext& node,
    std::string_view profile_name,
    double validation_overhead_s,
    double propagation_overhead_s,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    std::string_view difficulty_policy,
    int difficulty_window_blocks,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    const auto resolved_profile = ResolveMatMulServiceDifficultyProfile(
        chainman,
        profile_name,
        min_solve_time_s,
        max_solve_time_s,
        solve_time_multiplier,
        difficulty_policy,
        difficulty_window_blocks);

    UniValue result(UniValue::VOBJ);
    result.pushKV(
        "profile",
        BuildMatMulServiceDifficultyRecommendation(
            resolved_profile.recommendation,
            resolved_profile.resolution,
            validation_overhead_s,
            propagation_overhead_s,
            solver_parallelism,
            solver_duty_cycle_pct));
    result.pushKV(
        "challenge_profile",
        BuildMatMulChallengeResponse(
            chainman,
            node,
            resolved_profile.resolution.resolved_solve_time_s,
            validation_overhead_s,
            propagation_overhead_s,
            &resolved_profile.resolution,
            solver_parallelism,
            solver_duty_cycle_pct));
    return result;
}

static UniValue BuildMatMulServiceChallengeProfilesResponse(
    ChainstateManager& chainman,
    double validation_overhead_s,
    double propagation_overhead_s,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    std::string_view difficulty_policy,
    int difficulty_window_blocks,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("default_profile", "balanced");
    result.pushKV("default_difficulty_label", "normal");

    UniValue profiles(UniValue::VARR);
    for (const auto& spec : MATMUL_SERVICE_DIFFICULTY_PROFILE_SPECS) {
        const auto resolved_profile = ResolveMatMulServiceDifficultyProfile(
            chainman,
            spec.name,
            min_solve_time_s,
            max_solve_time_s,
            solve_time_multiplier,
            difficulty_policy,
            difficulty_window_blocks);
        profiles.push_back(
            BuildMatMulServiceDifficultyRecommendation(
                resolved_profile.recommendation,
                resolved_profile.resolution,
                validation_overhead_s,
                propagation_overhead_s,
                solver_parallelism,
                solver_duty_cycle_pct));
    }
    result.pushKV("profiles", std::move(profiles));
    return result;
}

static UniValue BuildIssuedMatMulServiceChallengeProfileResponse(
    ChainstateManager& chainman,
    const NodeContext& node,
    std::string_view purpose,
    std::string_view resource,
    std::string_view subject,
    std::string_view profile_name,
    int64_t expires_in_s,
    double validation_overhead_s,
    double propagation_overhead_s,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    std::string_view difficulty_policy,
    int difficulty_window_blocks,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    const auto resolved_profile = ResolveMatMulServiceDifficultyProfile(
        chainman,
        profile_name,
        min_solve_time_s,
        max_solve_time_s,
        solve_time_multiplier,
        difficulty_policy,
        difficulty_window_blocks);

    UniValue result(UniValue::VOBJ);
    result.pushKV(
        "profile",
        BuildMatMulServiceDifficultyRecommendation(
            resolved_profile.recommendation,
            resolved_profile.resolution,
            validation_overhead_s,
            propagation_overhead_s,
            solver_parallelism,
            solver_duty_cycle_pct));
    result.pushKV(
        "service_challenge",
        BuildMatMulServiceChallengeResponse(
            chainman,
            node,
            std::string{purpose},
            std::string{resource},
            std::string{subject},
            resolved_profile.recommendation.recommended_solve_time_s,
            expires_in_s,
            validation_overhead_s,
            propagation_overhead_s,
            difficulty_policy,
            difficulty_window_blocks,
            min_solve_time_s,
            max_solve_time_s,
            solver_parallelism,
            solver_duty_cycle_pct));
    return result;
}

static UniValue BuildMatMulServicePlanningObjective(
    const MatMulServicePlanningObjective& objective)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("mode", objective.mode);
    result.pushKV("requested_value", objective.requested_value);
    result.pushKV(
        "requested_sustained_solves_per_hour",
        objective.requested_sustained_solves_per_hour);
    result.pushKV(
        "requested_sustained_solves_per_day",
        objective.requested_sustained_solves_per_day);
    result.pushKV(
        "requested_mean_seconds_between_solves",
        objective.requested_mean_seconds_between_solves);
    result.pushKV("requested_total_target_s", objective.requested_total_target_s);
    result.pushKV(
        "requested_resolved_solve_time_s",
        objective.requested_resolved_solve_time_s);
    return result;
}

static UniValue BuildMatMulServicePlanningGap(
    const MatMulServicePlanningObjective& objective,
    const MatMulServicePlanningGap& gap)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("mode", objective.mode);
    result.pushKV("requested_value", objective.requested_value);
    result.pushKV("actual_value", gap.actual_value);
    result.pushKV("delta_value", gap.delta_value);
    result.pushKV("delta_pct", gap.delta_pct);
    result.pushKV("requested_total_target_s", objective.requested_total_target_s);
    result.pushKV("actual_total_target_s", gap.actual_total_target_s);
    result.pushKV("total_target_delta_s", gap.total_target_delta_s);
    result.pushKV(
        "requested_sustained_solves_per_hour",
        objective.requested_sustained_solves_per_hour);
    result.pushKV(
        "actual_sustained_solves_per_hour",
        gap.actual_sustained_solves_per_hour);
    result.pushKV(
        "requested_sustained_solves_per_day",
        objective.requested_sustained_solves_per_day);
    result.pushKV(
        "actual_sustained_solves_per_day",
        gap.actual_sustained_solves_per_day);
    result.pushKV(
        "requested_mean_seconds_between_solves",
        objective.requested_mean_seconds_between_solves);
    result.pushKV(
        "actual_mean_seconds_between_solves",
        gap.actual_mean_seconds_between_solves);
    result.pushKV(
        "required_effective_parallelism",
        gap.required_effective_parallelism);
    result.pushKV(
        "available_effective_parallelism",
        gap.available_effective_parallelism);
    result.pushKV(
        "effective_parallelism_gap",
        gap.effective_parallelism_gap);
    result.pushKV("headroom_pct", gap.headroom_pct);
    result.pushKV("objective_satisfied", gap.objective_satisfied);
    return result;
}

static MatMulServicePlanningProfileCandidate ResolveMatMulServicePlanningProfileCandidate(
    ChainstateManager& chainman,
    const MatMulServicePlanningObjective& objective,
    std::string_view profile_name,
    double validation_overhead_s,
    double propagation_overhead_s,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    std::string_view difficulty_policy,
    int difficulty_window_blocks,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    MatMulServicePlanningProfileCandidate candidate;
    candidate.resolved_profile = ResolveMatMulServiceDifficultyProfile(
        chainman,
        profile_name,
        min_solve_time_s,
        max_solve_time_s,
        solve_time_multiplier,
        difficulty_policy,
        difficulty_window_blocks);
    candidate.resolved_total_target_s =
        candidate.resolved_profile.resolution.resolved_solve_time_s +
        validation_overhead_s + propagation_overhead_s;
    candidate.operator_capacity = ResolveMatMulOperatorCapacityPlan(
        candidate.resolved_total_target_s,
        solver_parallelism,
        solver_duty_cycle_pct);
    candidate.gap = BuildMatMulServicePlanningGap(
        objective,
        candidate.operator_capacity,
        candidate.resolved_total_target_s);
    return candidate;
}

static UniValue BuildMatMulServicePlanningProfileCandidate(
    const MatMulServicePlanningObjective& objective,
    const MatMulServicePlanningProfileCandidate& candidate,
    double validation_overhead_s,
    double propagation_overhead_s,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    UniValue result = BuildMatMulServiceDifficultyRecommendation(
        candidate.resolved_profile.recommendation,
        candidate.resolved_profile.resolution,
        validation_overhead_s,
        propagation_overhead_s,
        solver_parallelism,
        solver_duty_cycle_pct);
    result.pushKV("resolved_total_target_s", candidate.resolved_total_target_s);
    result.pushKV("objective_satisfied", candidate.gap.objective_satisfied);
    result.pushKV(
        "objective_gap",
        BuildMatMulServicePlanningGap(objective, candidate.gap));
    return result;
}

static UniValue BuildMatMulServiceChallengePlanResponse(
    ChainstateManager& chainman,
    const NodeContext& node,
    std::string_view objective_mode,
    double objective_value,
    double validation_overhead_s,
    double propagation_overhead_s,
    std::string_view difficulty_policy,
    int difficulty_window_blocks,
    double min_solve_time_s,
    double max_solve_time_s,
    int solver_parallelism,
    double solver_duty_cycle_pct)
{
    const auto objective = ResolveMatMulServicePlanningObjective(
        objective_mode,
        objective_value,
        validation_overhead_s,
        propagation_overhead_s,
        solver_parallelism,
        solver_duty_cycle_pct);
    const Consensus::Params& consensus = chainman.GetConsensus();
    const CBlockIndex* active_tip = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip());
    const double base_solve_time_s = ResolveMatMulServiceObjectiveBaseSolveTime(
        consensus,
        active_tip,
        difficulty_policy,
        objective.requested_resolved_solve_time_s,
        difficulty_window_blocks);
    const auto planning_resolution = ResolveMatMulServiceDifficultyPolicy(
        consensus,
        active_tip,
        difficulty_policy,
        base_solve_time_s,
        difficulty_window_blocks,
        min_solve_time_s,
        max_solve_time_s);
    const double resolved_total_target_s =
        planning_resolution.resolved_solve_time_s +
        validation_overhead_s + propagation_overhead_s;
    const auto operator_capacity = ResolveMatMulOperatorCapacityPlan(
        resolved_total_target_s,
        solver_parallelism,
        solver_duty_cycle_pct);
    const auto gap = BuildMatMulServicePlanningGap(
        objective,
        operator_capacity,
        resolved_total_target_s);

    std::vector<MatMulServicePlanningProfileCandidate> candidates;
    candidates.reserve(MATMUL_SERVICE_DIFFICULTY_PROFILE_SPECS.size());
    for (const auto& spec : MATMUL_SERVICE_DIFFICULTY_PROFILE_SPECS) {
        const double solve_time_multiplier =
            base_solve_time_s /
            (static_cast<double>(consensus.nPowTargetSpacing) * spec.solve_time_ratio);
        candidates.push_back(
            ResolveMatMulServicePlanningProfileCandidate(
                chainman,
                objective,
                spec.name,
                validation_overhead_s,
                propagation_overhead_s,
                min_solve_time_s,
                max_solve_time_s,
                solve_time_multiplier,
                difficulty_policy,
                difficulty_window_blocks,
                solver_parallelism,
                solver_duty_cycle_pct));
    }
    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const auto& lhs, const auto& rhs) {
            const double lhs_gap = std::abs(lhs.gap.delta_pct);
            const double rhs_gap = std::abs(rhs.gap.delta_pct);
            if (lhs_gap != rhs_gap) return lhs_gap < rhs_gap;
            const double lhs_multiplier_gap =
                std::abs(std::log(lhs.resolved_profile.recommendation.solve_time_multiplier));
            const double rhs_multiplier_gap =
                std::abs(std::log(rhs.resolved_profile.recommendation.solve_time_multiplier));
            if (lhs_multiplier_gap != rhs_multiplier_gap) {
                return lhs_multiplier_gap < rhs_multiplier_gap;
            }
            return lhs.resolved_profile.recommendation.effort_tier <
                rhs.resolved_profile.recommendation.effort_tier;
        });

    UniValue result(UniValue::VOBJ);
    result.pushKV("objective", BuildMatMulServicePlanningObjective(objective));

    UniValue plan(UniValue::VOBJ);
    plan.pushKV("objective_satisfied", gap.objective_satisfied);
    plan.pushKV("requested_base_solve_time_s", base_solve_time_s);
    plan.pushKV(
        "resolved_target_solve_time_s",
        planning_resolution.resolved_solve_time_s);
    plan.pushKV("resolved_total_target_s", resolved_total_target_s);
    plan.pushKV("validation_overhead_s", validation_overhead_s);
    plan.pushKV("propagation_overhead_s", propagation_overhead_s);
    plan.pushKV(
        "difficulty_resolution",
        BuildMatMulServiceDifficultyResolution(planning_resolution));
    plan.pushKV(
        "operator_capacity",
        BuildMatMulOperatorCapacityPlan(
            resolved_total_target_s,
            solver_parallelism,
            solver_duty_cycle_pct));
    plan.pushKV(
        "objective_gap",
        BuildMatMulServicePlanningGap(objective, gap));
    plan.pushKV(
        "issue_defaults",
        BuildMatMulServiceDirectIssueDefaults(
            base_solve_time_s,
            validation_overhead_s,
            propagation_overhead_s,
            planning_resolution,
            solver_parallelism,
            solver_duty_cycle_pct));
    result.pushKV("plan", std::move(plan));

    result.pushKV(
        "recommended_profile",
        BuildMatMulServicePlanningProfileCandidate(
            objective,
            candidates.front(),
            validation_overhead_s,
            propagation_overhead_s,
            solver_parallelism,
            solver_duty_cycle_pct));

    UniValue candidate_profiles(UniValue::VARR);
    for (const auto& candidate : candidates) {
        candidate_profiles.push_back(
            BuildMatMulServicePlanningProfileCandidate(
                objective,
                candidate,
                validation_overhead_s,
                propagation_overhead_s,
                solver_parallelism,
                solver_duty_cycle_pct));
    }
    result.pushKV("candidate_profiles", std::move(candidate_profiles));
    result.pushKV(
        "challenge_profile",
        BuildMatMulChallengeResponse(
            chainman,
            node,
            planning_resolution.resolved_solve_time_s,
            validation_overhead_s,
            propagation_overhead_s,
            &planning_resolution,
            solver_parallelism,
            solver_duty_cycle_pct));
    return result;
}

static arith_uint256 ComputeExpectedMatMulServiceTarget(
    ChainstateManager& chainman,
    const uint256& anchor_hash,
    int anchor_height,
    int64_t issued_at,
    int64_t target_solve_time_ms)
{
    if (anchor_height < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: anchor height must be non-negative");
    }
    if (target_solve_time_ms <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: target_solve_time_s must be positive");
    }

    const Consensus::Params& consensus = chainman.GetConsensus();
    uint32_t current_bits{0};
    {
        LOCK(cs_main);
        const CBlockIndex* pindex_anchor = chainman.m_blockman.LookupBlockIndex(anchor_hash);
        if (pindex_anchor == nullptr) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: unknown anchor block");
        }
        if (pindex_anchor->nHeight != anchor_height) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: anchor height mismatch");
        }
        const CBlockIndex* active_anchor = chainman.ActiveChain()[anchor_height];
        if (active_anchor != pindex_anchor) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: anchor block is not on the active chain");
        }

        CBlockHeader next_header;
        next_header.hashPrevBlock = anchor_hash;
        next_header.nTime = static_cast<uint32_t>(issued_at);
        current_bits = GetNextWorkRequired(pindex_anchor, &next_header, consensus);
    }

    const arith_uint256 current_target{*CHECK_NONFATAL(DeriveTarget(current_bits, consensus.powLimit))};
    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const int64_t current_solve_time_ms = static_cast<int64_t>(std::llround(consensus.nPowTargetSpacing * 1000.0));
    return ScaleTargetForSolveTime(
        current_target,
        current_solve_time_ms,
        target_solve_time_ms,
        pow_limit);
}

static MatMulServiceChallengeContext ParseMatMulServiceChallenge(
    ChainstateManager& chainman,
    const UniValue& challenge_value)
{
    try {
        const Consensus::Params& consensus = chainman.GetConsensus();
        const UniValue& challenge_obj = challenge_value.get_obj();
        if (challenge_obj.find_value("kind").isNull() ||
            challenge_obj.find_value("kind").get_str() != MATMUL_SERVICE_KIND) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "challenge.kind must be matmul_service_challenge_v1");
        }

        MatMulServiceChallengeContext ctx;
        const UniValue& binding = challenge_obj.find_value("binding").get_obj();
        ctx.chain = chainman.GetParams().GetChainTypeString();
        ctx.purpose = binding.find_value("purpose").get_str();
        ctx.resource = binding.find_value("resource").get_str();
        ctx.subject = binding.find_value("subject").get_str();
        if (ctx.purpose.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: purpose must be non-empty");
        }
        if (ctx.resource.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: resource must be non-empty");
        }
        if (ctx.subject.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: subject must be non-empty");
        }
        if (ctx.purpose.size() > MATMUL_SERVICE_MAX_TEXT_BYTES) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "invalid service challenge: purpose must be at most %u bytes",
                    static_cast<unsigned>(MATMUL_SERVICE_MAX_TEXT_BYTES)));
        }
        if (ctx.resource.size() > MATMUL_SERVICE_MAX_TEXT_BYTES) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "invalid service challenge: resource must be at most %u bytes",
                    static_cast<unsigned>(MATMUL_SERVICE_MAX_TEXT_BYTES)));
        }
        if (ctx.subject.size() > MATMUL_SERVICE_MAX_TEXT_BYTES) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "invalid service challenge: subject must be at most %u bytes",
                    static_cast<unsigned>(MATMUL_SERVICE_MAX_TEXT_BYTES)));
        }
        ctx.resource_hash = HashMatMulServiceText("resource", ctx.resource);
        ctx.subject_hash = HashMatMulServiceText("subject", ctx.subject);
        ctx.binding_hash = ComputeMatMulServiceBindingHash(ctx.chain, ctx.purpose, ctx.resource_hash, ctx.subject_hash);
        ctx.salt = ParseUint256HexOrThrow(
            binding.find_value("salt").get_str(),
            "invalid service challenge: binding.salt must be 64 hex characters");
        ctx.anchor_height = ParseIntegralServiceField<int>(
            binding.find_value("anchor_height"),
            "anchor_height");
        ctx.anchor_hash = ParseUint256HexOrThrow(
            binding.find_value("anchor_hash").get_str(),
            "invalid service challenge: binding.anchor_hash must be 64 hex characters");
        ctx.issued_at = ParseIntegralServiceField<int64_t>(
            challenge_obj.find_value("issued_at"),
            "issued_at");
        ctx.expires_at = ParseIntegralServiceField<int64_t>(
            challenge_obj.find_value("expires_at"),
            "expires_at");
        if (ctx.expires_at < ctx.issued_at) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "invalid service challenge: expires_at must be greater than or equal to issued_at");
        }

        const UniValue& challenge = challenge_obj.find_value("challenge").get_obj();
        const UniValue& header_context = challenge.find_value("header_context").get_obj();
        const UniValue& matmul = challenge.find_value("matmul").get_obj();
        const UniValue& service_profile = challenge.find_value("service_profile").get_obj();
        ctx.solve_time_target_s =
            ParseNumericServiceField(service_profile.find_value("solve_time_target_s"), "solve_time_target_s");
        ctx.validation_overhead_s =
            ParseNumericServiceField(service_profile.find_value("validation_overhead_s"), "validation_overhead_s");
        ctx.propagation_overhead_s =
            ParseNumericServiceField(service_profile.find_value("propagation_overhead_s"), "propagation_overhead_s");
        if (!(ctx.solve_time_target_s > 0.0)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: target_solve_time_s must be positive");
        }
        if (ctx.validation_overhead_s < 0.0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: validation_overhead_s must be non-negative");
        }
        if (ctx.propagation_overhead_s < 0.0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid service challenge: propagation_overhead_s must be non-negative");
        }
        const UniValue& difficulty_resolution_value = service_profile.find_value("difficulty_resolution");
        if (!difficulty_resolution_value.isNull()) {
            const UniValue& difficulty_resolution = difficulty_resolution_value.get_obj();
            ctx.difficulty_policy = ParseMatMulServiceDifficultyPolicy(
                difficulty_resolution.find_value("mode").get_str());
            ctx.base_solve_time_s =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("base_solve_time_s"),
                    "difficulty_resolution.base_solve_time_s");
            ctx.adjusted_solve_time_s =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("adjusted_solve_time_s"),
                    "difficulty_resolution.adjusted_solve_time_s");
            ctx.min_solve_time_s =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("min_solve_time_s"),
                    "difficulty_resolution.min_solve_time_s");
            ctx.max_solve_time_s =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("max_solve_time_s"),
                    "difficulty_resolution.max_solve_time_s");
            ctx.difficulty_window_blocks = ParseIntegralServiceField<int>(
                difficulty_resolution.find_value("window_blocks"),
                "difficulty_resolution.window_blocks");
            ctx.observed_interval_count = ParseIntegralServiceField<size_t>(
                difficulty_resolution.find_value("observed_interval_count"),
                "difficulty_resolution.observed_interval_count");
            ctx.observed_mean_interval_s =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("observed_mean_interval_s"),
                    "difficulty_resolution.observed_mean_interval_s");
            ctx.network_target_s =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("network_target_s"),
                    "difficulty_resolution.network_target_s");
            ctx.interval_scale =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("interval_scale"),
                    "difficulty_resolution.interval_scale");
            ctx.difficulty_clamped = difficulty_resolution.find_value("clamped").get_bool();
            const double resolved_solve_time_s =
                ParseNumericServiceField(
                    difficulty_resolution.find_value("resolved_solve_time_s"),
                    "difficulty_resolution.resolved_solve_time_s");
            if (resolved_solve_time_s != ctx.solve_time_target_s) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "invalid service challenge: difficulty_resolution.resolved_solve_time_s must match solve_time_target_s");
            }
        } else {
            ctx.difficulty_policy = MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED;
            ctx.base_solve_time_s = ctx.solve_time_target_s;
            ctx.adjusted_solve_time_s = ctx.solve_time_target_s;
            ctx.min_solve_time_s = ctx.solve_time_target_s;
            ctx.max_solve_time_s = ctx.solve_time_target_s;
            ctx.difficulty_window_blocks = MATMUL_SERVICE_DIFFICULTY_POLICY_DEFAULT_WINDOW_BLOCKS;
            ctx.observed_interval_count = 0;
            ctx.observed_mean_interval_s = static_cast<double>(consensus.nPowTargetSpacing);
            ctx.network_target_s = static_cast<double>(consensus.nPowTargetSpacing);
            ctx.interval_scale = 1.0;
            ctx.difficulty_clamped = false;
        }
        ctx.n = static_cast<uint32_t>(consensus.nMatMulDimension);
        ctx.b = static_cast<uint32_t>(consensus.nMatMulTranscriptBlockSize);
        ctx.r = static_cast<uint32_t>(consensus.nMatMulNoiseRank);
        const int64_t target_solve_time_ms = static_cast<int64_t>(std::llround(ctx.solve_time_target_s * 1000.0));
        const int64_t validation_overhead_ms = static_cast<int64_t>(std::llround(ctx.validation_overhead_s * 1000.0));
        const int64_t propagation_overhead_ms = static_cast<int64_t>(std::llround(ctx.propagation_overhead_s * 1000.0));
        ctx.challenge_id = ComputeMatMulServiceChallengeId(
            ctx.chain,
            ctx.binding_hash,
            ctx.salt,
            ctx.anchor_hash,
            ctx.anchor_height,
            ctx.issued_at,
            ctx.expires_at,
            target_solve_time_ms,
            validation_overhead_ms,
            propagation_overhead_ms);

        ctx.header.nVersion = ParseIntegralServiceField<int32_t>(
            header_context.find_value("version"),
            "header_context.version");
        ctx.header.hashPrevBlock = ctx.anchor_hash;
        ctx.header.hashMerkleRoot = DeriveMatMulServiceMerkleRoot(ctx.challenge_id, ctx.binding_hash);
        ctx.header.nTime = static_cast<uint32_t>(ctx.issued_at);
        ctx.header.nNonce64 = 0;
        ctx.header.nNonce = 0;
        ctx.header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        ctx.header.seed_a = DeriveMatMulServiceSeed(ctx.challenge_id, ctx.anchor_hash, "seed_a");
        ctx.header.seed_b = DeriveMatMulServiceSeed(ctx.challenge_id, ctx.anchor_hash, "seed_b");
        const CBlockIndex* anchor_tip{nullptr};
        {
            LOCK(cs_main);
            anchor_tip = chainman.m_blockman.LookupBlockIndex(ctx.anchor_hash);
        }
        const auto expected_difficulty_resolution = ResolveMatMulServiceDifficultyPolicy(
            consensus,
            anchor_tip,
            ctx.difficulty_policy,
            ctx.base_solve_time_s,
            ctx.difficulty_window_blocks,
            ctx.min_solve_time_s,
            ctx.max_solve_time_s);
        if (expected_difficulty_resolution.resolved_solve_time_s != ctx.solve_time_target_s) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "invalid service challenge: difficulty_resolution does not match the anchored network conditions");
        }
        ctx.adjusted_solve_time_s = expected_difficulty_resolution.adjusted_solve_time_s;
        ctx.observed_interval_count = expected_difficulty_resolution.observed_interval_count;
        ctx.observed_mean_interval_s = expected_difficulty_resolution.observed_mean_interval_s;
        ctx.network_target_s = expected_difficulty_resolution.network_target_s;
        ctx.interval_scale = expected_difficulty_resolution.interval_scale;
        ctx.difficulty_clamped = expected_difficulty_resolution.clamped;
        const arith_uint256 expected_target = ComputeExpectedMatMulServiceTarget(
            chainman,
            ctx.anchor_hash,
            ctx.anchor_height,
            ctx.issued_at,
            target_solve_time_ms);
        ctx.header.nBits = expected_target.GetCompact();
        ctx.target = *CHECK_NONFATAL(DeriveTarget(ctx.header.nBits, consensus.powLimit));
        (void)challenge;
        (void)matmul;
        return ctx;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid service challenge: %s", e.what()));
    }
}

static std::optional<std::string> GetMatMulServiceChallengeMismatch(
    const UniValue& challenge_value,
    const MatMulServiceChallengeContext& ctx)
{
    const UniValue& challenge_obj = challenge_value.get_obj();
    if (challenge_obj.find_value("challenge_id").get_str() != ctx.challenge_id.GetHex()) return "challenge_id";
    if (ParseIntegralServiceField<int64_t>(challenge_obj.find_value("issued_at"), "issued_at") != ctx.issued_at) return "issued_at";
    if (ParseIntegralServiceField<int64_t>(challenge_obj.find_value("expires_at"), "expires_at") != ctx.expires_at) return "expires_at";
    if (ParseIntegralServiceField<int64_t>(challenge_obj.find_value("expires_in_s"), "expires_in_s") != (ctx.expires_at - ctx.issued_at)) return "expires_in_s";

    const UniValue& binding = challenge_obj.find_value("binding").get_obj();
    if (binding.find_value("chain").get_str() != ctx.chain) return "binding.chain";
    if (binding.find_value("purpose").get_str() != ctx.purpose) return "binding.purpose";
    if (binding.find_value("resource").get_str() != ctx.resource) return "binding.resource";
    if (binding.find_value("subject").get_str() != ctx.subject) return "binding.subject";
    if (binding.find_value("resource_hash").get_str() != ctx.resource_hash.GetHex()) return "binding.resource_hash";
    if (binding.find_value("subject_hash").get_str() != ctx.subject_hash.GetHex()) return "binding.subject_hash";
    if (binding.find_value("salt").get_str() != ctx.salt.GetHex()) return "binding.salt";
    if (ParseIntegralServiceField<int>(binding.find_value("anchor_height"), "binding.anchor_height") != ctx.anchor_height) return "binding.anchor_height";
    if (binding.find_value("anchor_hash").get_str() != ctx.anchor_hash.GetHex()) return "binding.anchor_hash";
    if (binding.find_value("challenge_id_rule").get_str() != MATMUL_SERVICE_CHALLENGE_ID_RULE) return "binding.challenge_id_rule";
    if (binding.find_value("seed_derivation_rule").get_str() != MATMUL_SERVICE_SEED_DERIVATION_RULE) return "binding.seed_derivation_rule";

    const UniValue& proof_policy = challenge_obj.find_value("proof_policy").get_obj();
    if (proof_policy.find_value("verification_rule").get_str() != MATMUL_SERVICE_VERIFICATION_RULE) return "proof_policy.verification_rule";
    if (proof_policy.find_value("sigma_gate_applied").get_bool()) return "proof_policy.sigma_gate_applied";
    if (!proof_policy.find_value("expiration_enforced").get_bool()) return "proof_policy.expiration_enforced";
    if (!proof_policy.find_value("challenge_id_required").get_bool()) return "proof_policy.challenge_id_required";
    const std::string replay_protection = proof_policy.find_value("replay_protection").get_str();
    if (replay_protection != "application_redeem_challenge_id" &&
        replay_protection != MATMUL_SERVICE_REDEEM_RPC) {
        return "proof_policy.replay_protection";
    }
    const UniValue& redeem_rpc = proof_policy.find_value("redeem_rpc");
    if (!redeem_rpc.isNull() && redeem_rpc.get_str() != MATMUL_SERVICE_REDEEM_RPC) {
        return "proof_policy.redeem_rpc";
    }
    const UniValue& solve_rpc = proof_policy.find_value("solve_rpc");
    if (!solve_rpc.isNull() && solve_rpc.get_str() != MATMUL_SERVICE_SOLVE_RPC) {
        return "proof_policy.solve_rpc";
    }
    const UniValue& locally_issued_required = proof_policy.find_value("locally_issued_required");
    if (!locally_issued_required.isNull() && !locally_issued_required.get_bool()) {
        return "proof_policy.locally_issued_required";
    }
    const UniValue& issued_challenge_store = proof_policy.find_value("issued_challenge_store");
    if (!issued_challenge_store.isNull() &&
        issued_challenge_store.get_str() != "process_memory" &&
        issued_challenge_store.get_str() != MATMUL_SERVICE_ISSUED_STORE_LOCAL_PERSISTENT_FILE &&
        issued_challenge_store.get_str() != MATMUL_SERVICE_ISSUED_STORE_SHARED_FILE_LOCK_STORE) {
        return "proof_policy.issued_challenge_store";
    }
    const UniValue& issued_challenge_scope = proof_policy.find_value("issued_challenge_scope");
    if (!issued_challenge_scope.isNull() &&
        issued_challenge_scope.get_str() != MATMUL_SERVICE_ISSUED_SCOPE_NODE_LOCAL &&
        issued_challenge_scope.get_str() != MATMUL_SERVICE_ISSUED_SCOPE_SHARED_FILE) {
        return "proof_policy.issued_challenge_scope";
    }

    const UniValue& challenge = challenge_obj.find_value("challenge").get_obj();
    if (challenge.find_value("chain").get_str() != ctx.chain) return "challenge.chain";
    if (challenge.find_value("algorithm").get_str() != "matmul") return "challenge.algorithm";
    if (ParseIntegralServiceField<int>(challenge.find_value("height"), "challenge.height") != ctx.anchor_height + 1) return "challenge.height";
    if (challenge.find_value("previousblockhash").get_str() != ctx.anchor_hash.GetHex()) return "challenge.previousblockhash";
    if (ParseIntegralServiceField<int64_t>(challenge.find_value("mintime"), "challenge.mintime") != ctx.issued_at) return "challenge.mintime";
    if (challenge.find_value("bits").get_str() != strprintf("%08x", ctx.header.nBits)) return "challenge.bits";
    if (challenge.find_value("target").get_str() != ArithToUint256(ctx.target).GetHex()) return "challenge.target";

    const UniValue& header_context = challenge.find_value("header_context").get_obj();
    if (ParseIntegralServiceField<int32_t>(header_context.find_value("version"), "challenge.header_context.version") != ctx.header.nVersion) return "challenge.header_context.version";
    if (header_context.find_value("previousblockhash").get_str() != ctx.header.hashPrevBlock.GetHex()) return "challenge.header_context.previousblockhash";
    if (header_context.find_value("merkleroot").get_str() != ctx.header.hashMerkleRoot.GetHex()) return "challenge.header_context.merkleroot";
    if (ParseIntegralServiceField<int64_t>(header_context.find_value("time"), "challenge.header_context.time") != ctx.issued_at) return "challenge.header_context.time";
    if (header_context.find_value("bits").get_str() != strprintf("%08x", ctx.header.nBits)) return "challenge.header_context.bits";
    if (ParseIntegralServiceField<uint64_t>(header_context.find_value("nonce64_start"), "challenge.header_context.nonce64_start") != 0) return "challenge.header_context.nonce64_start";
    if (ParseIntegralServiceField<uint32_t>(header_context.find_value("matmul_dim"), "challenge.header_context.matmul_dim") != ctx.n) return "challenge.header_context.matmul_dim";
    if (header_context.find_value("seed_a").get_str() != ctx.header.seed_a.GetHex()) return "challenge.header_context.seed_a";
    if (header_context.find_value("seed_b").get_str() != ctx.header.seed_b.GetHex()) return "challenge.header_context.seed_b";

    const UniValue& matmul = challenge.find_value("matmul").get_obj();
    if (ParseIntegralServiceField<uint32_t>(matmul.find_value("n"), "challenge.matmul.n") != ctx.n) return "challenge.matmul.n";
    if (ParseIntegralServiceField<uint32_t>(matmul.find_value("b"), "challenge.matmul.b") != ctx.b) return "challenge.matmul.b";
    if (ParseIntegralServiceField<uint32_t>(matmul.find_value("r"), "challenge.matmul.r") != ctx.r) return "challenge.matmul.r";
    if (ParseIntegralServiceField<uint64_t>(matmul.find_value("q"), "challenge.matmul.q") != static_cast<uint64_t>(matmul::field::MODULUS)) return "challenge.matmul.q";
    if (matmul.find_value("seed_a").get_str() != ctx.header.seed_a.GetHex()) return "challenge.matmul.seed_a";
    if (matmul.find_value("seed_b").get_str() != ctx.header.seed_b.GetHex()) return "challenge.matmul.seed_b";

    const UniValue& service_profile = challenge.find_value("service_profile").get_obj();
    if (ParseNumericServiceField(service_profile.find_value("solve_time_target_s"), "challenge.service_profile.solve_time_target_s") != ctx.solve_time_target_s) return "challenge.service_profile.solve_time_target_s";
    if (ParseNumericServiceField(service_profile.find_value("validation_overhead_s"), "challenge.service_profile.validation_overhead_s") != ctx.validation_overhead_s) return "challenge.service_profile.validation_overhead_s";
    if (ParseNumericServiceField(service_profile.find_value("propagation_overhead_s"), "challenge.service_profile.propagation_overhead_s") != ctx.propagation_overhead_s) return "challenge.service_profile.propagation_overhead_s";
    const UniValue& difficulty_resolution = service_profile.find_value("difficulty_resolution");
    if (!difficulty_resolution.isNull()) {
        const UniValue& difficulty_resolution_obj = difficulty_resolution.get_obj();
        if (difficulty_resolution_obj.find_value("mode").get_str() != ctx.difficulty_policy) return "challenge.service_profile.difficulty_resolution.mode";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("base_solve_time_s"), "challenge.service_profile.difficulty_resolution.base_solve_time_s") != ctx.base_solve_time_s) return "challenge.service_profile.difficulty_resolution.base_solve_time_s";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("adjusted_solve_time_s"), "challenge.service_profile.difficulty_resolution.adjusted_solve_time_s") != ctx.adjusted_solve_time_s) return "challenge.service_profile.difficulty_resolution.adjusted_solve_time_s";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("resolved_solve_time_s"), "challenge.service_profile.difficulty_resolution.resolved_solve_time_s") != ctx.solve_time_target_s) return "challenge.service_profile.difficulty_resolution.resolved_solve_time_s";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("min_solve_time_s"), "challenge.service_profile.difficulty_resolution.min_solve_time_s") != ctx.min_solve_time_s) return "challenge.service_profile.difficulty_resolution.min_solve_time_s";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("max_solve_time_s"), "challenge.service_profile.difficulty_resolution.max_solve_time_s") != ctx.max_solve_time_s) return "challenge.service_profile.difficulty_resolution.max_solve_time_s";
        if (ParseIntegralServiceField<int>(difficulty_resolution_obj.find_value("window_blocks"), "challenge.service_profile.difficulty_resolution.window_blocks") != ctx.difficulty_window_blocks) return "challenge.service_profile.difficulty_resolution.window_blocks";
        if (ParseIntegralServiceField<size_t>(difficulty_resolution_obj.find_value("observed_interval_count"), "challenge.service_profile.difficulty_resolution.observed_interval_count") != ctx.observed_interval_count) return "challenge.service_profile.difficulty_resolution.observed_interval_count";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("observed_mean_interval_s"), "challenge.service_profile.difficulty_resolution.observed_mean_interval_s") != ctx.observed_mean_interval_s) return "challenge.service_profile.difficulty_resolution.observed_mean_interval_s";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("network_target_s"), "challenge.service_profile.difficulty_resolution.network_target_s") != ctx.network_target_s) return "challenge.service_profile.difficulty_resolution.network_target_s";
        if (ParseNumericServiceField(difficulty_resolution_obj.find_value("interval_scale"), "challenge.service_profile.difficulty_resolution.interval_scale") != ctx.interval_scale) return "challenge.service_profile.difficulty_resolution.interval_scale";
        if (difficulty_resolution_obj.find_value("clamped").get_bool() != ctx.difficulty_clamped) return "challenge.service_profile.difficulty_resolution.clamped";
    }

    return std::nullopt;
}

static matmul::PowState BuildMatMulServicePowState(
    const MatMulServiceChallengeContext& ctx,
    uint64_t nonce64,
    const uint256& digest)
{
    matmul::PowState state;
    state.version = ctx.header.nVersion;
    state.previous_block_hash = ctx.header.hashPrevBlock;
    state.merkle_root = ctx.header.hashMerkleRoot;
    state.time = ctx.header.nTime;
    state.bits = ctx.header.nBits;
    state.seed_a = ctx.header.seed_a;
    state.seed_b = ctx.header.seed_b;
    state.nonce = nonce64;
    state.matmul_dim = ctx.header.matmul_dim;
    state.digest = digest;
    return state;
}

static matmul::PowConfig BuildMatMulServicePowConfig(const MatMulServiceChallengeContext& ctx)
{
    return matmul::PowConfig{
        .n = ctx.n,
        .b = ctx.b,
        .r = ctx.r,
        .target = ctx.target,
    };
}

static UniValue EvaluateMatMulServiceProof(
    const MatMulServiceChallengeContext& ctx,
    const std::string& nonce64_hex,
    const std::string& digest_hex,
    bool& transcript_valid)
{
    uint64_t nonce64{0};
    if (!ParseNonce64Hex(nonce64_hex, nonce64)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "nonce64_hex must be exactly 16 hex characters");
    }
    if (digest_hex.size() != 64 || !IsHex(digest_hex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "digest_hex must be exactly 64 hex characters");
    }

    matmul::PowState state = BuildMatMulServicePowState(
        ctx,
        nonce64,
        ParseUint256HexOrThrow(digest_hex, "digest_hex must be exactly 64 hex characters"));
    const matmul::PowConfig config = BuildMatMulServicePowConfig(ctx);

    const bool commitment_valid = matmul::VerifyCommitment(state, config);
    transcript_valid = commitment_valid && matmul::Verify(state, config);
    UniValue proof(UniValue::VOBJ);
    proof.pushKV("nonce64_hex", nonce64_hex);
    proof.pushKV("digest", digest_hex);
    proof.pushKV("sigma", matmul::DeriveSigma(state).GetHex());
    proof.pushKV("meets_target", commitment_valid);
    proof.pushKV("commitment_valid", commitment_valid);
    proof.pushKV("transcript_valid", transcript_valid);
    return proof;
}

static UniValue BuildMatMulServiceProofResult(
    const ArgsManager& args,
    ChainstateManager& chainman,
    const UniValue& challenge_value,
    const std::string& nonce64_hex,
    const std::string& digest_hex,
    bool include_local_registry_status = true)
{
    const MatMulServiceChallengeContext ctx = ParseMatMulServiceChallenge(chainman, challenge_value);
    const int64_t checked_at = GetTime();
    UniValue result(UniValue::VOBJ);
    result.pushKV("challenge_id", ctx.challenge_id.GetHex());
    result.pushKV("checked_at", checked_at);
    result.pushKV("expires_at", ctx.expires_at);

    MatMulServiceChallengeRegistryStatus registry_status;
    registry_status.local_registry_status_checked = include_local_registry_status;
    if (include_local_registry_status) {
        registry_status = GetMatMulServiceChallengeRegistryStatus(
            args,
            ctx.challenge_id,
            checked_at,
            ctx.expires_at);
    }
    AppendMatMulServiceRegistryStatus(result, registry_status);

    if (const auto mismatch = GetMatMulServiceChallengeMismatch(challenge_value, ctx)) {
        result.pushKV("valid", false);
        result.pushKV("expired", false);
        result.pushKV("reason", "challenge_mismatch");
        result.pushKV("mismatch_field", *mismatch);
        return result;
    }

    if (ctx.expires_at < checked_at) {
        result.pushKV("valid", false);
        result.pushKV("expired", true);
        result.pushKV("reason", "expired");
        return result;
    }

    bool transcript_valid{false};
    UniValue proof = EvaluateMatMulServiceProof(ctx, nonce64_hex, digest_hex, transcript_valid);

    result.pushKV("valid", transcript_valid);
    result.pushKV("expired", false);
    result.pushKV("reason", transcript_valid ? "ok" : "invalid_proof");
    result.pushKV("proof", std::move(proof));
    return result;
}

static UniValue BuildMatMulServiceRedeemResult(
    const ArgsManager& args,
    ChainstateManager& chainman,
    const UniValue& challenge_value,
    const std::string& nonce64_hex,
    const std::string& digest_hex)
{
    const MatMulServiceChallengeContext ctx = ParseMatMulServiceChallenge(chainman, challenge_value);
    const int64_t checked_at = GetTime();
    UniValue result(UniValue::VOBJ);
    result.pushKV("challenge_id", ctx.challenge_id.GetHex());
    result.pushKV("checked_at", checked_at);
    result.pushKV("expires_at", ctx.expires_at);

    if (const auto mismatch = GetMatMulServiceChallengeMismatch(challenge_value, ctx)) {
        const auto registry_status = GetMatMulServiceChallengeRegistryStatus(
            args,
            ctx.challenge_id,
            checked_at,
            ctx.expires_at);
        AppendMatMulServiceRegistryStatus(result, registry_status);
        result.pushKV("valid", false);
        result.pushKV("expired", false);
        result.pushKV("reason", "challenge_mismatch");
        result.pushKV("mismatch_field", *mismatch);
        return result;
    }

    if (ctx.expires_at < checked_at) {
        const auto registry_status = GetMatMulServiceChallengeRegistryStatus(
            args,
            ctx.challenge_id,
            checked_at,
            ctx.expires_at);
        AppendMatMulServiceRegistryStatus(result, registry_status);
        result.pushKV("valid", false);
        result.pushKV("expired", true);
        result.pushKV("reason", "expired");
        return result;
    }

    auto registry_status = GetMatMulServiceChallengeRegistryStatus(
        args,
        ctx.challenge_id,
        checked_at,
        ctx.expires_at);
    if (!registry_status.issued_by_local_node) {
        AppendMatMulServiceRegistryStatus(result, registry_status);
        result.pushKV("valid", false);
        result.pushKV("expired", false);
        result.pushKV("reason", "unknown_challenge");
        return result;
    }
    if (registry_status.redeemed) {
        registry_status.redeemable = false;
        AppendMatMulServiceRegistryStatus(result, registry_status);
        result.pushKV("valid", false);
        result.pushKV("expired", false);
        result.pushKV("reason", "already_redeemed");
        return result;
    }

    bool transcript_valid{false};
    UniValue proof = EvaluateMatMulServiceProof(ctx, nonce64_hex, digest_hex, transcript_valid);
    if (!transcript_valid) {
        registry_status.redeemable = true;
        AppendMatMulServiceRegistryStatus(result, registry_status);
        result.pushKV("valid", false);
        result.pushKV("expired", false);
        result.pushKV("reason", "invalid_proof");
        result.pushKV("proof", std::move(proof));
        return result;
    }

    registry_status = RedeemMatMulServiceChallenge(args, ctx.challenge_id, checked_at, ctx.expires_at);
    if (!registry_status.issued_by_local_node) {
        AppendMatMulServiceRegistryStatus(result, registry_status);
        result.pushKV("valid", false);
        result.pushKV("expired", false);
        result.pushKV("reason", "unknown_challenge");
        return result;
    }
    if (!registry_status.redeemed_now) {
        registry_status.redeemable = false;
        AppendMatMulServiceRegistryStatus(result, registry_status);
        result.pushKV("valid", false);
        result.pushKV("expired", false);
        result.pushKV("reason", "already_redeemed");
        return result;
    }
    registry_status.redeemable = false;
    AppendMatMulServiceRegistryStatus(result, registry_status);
    result.pushKV("valid", true);
    result.pushKV("expired", false);
    result.pushKV("reason", "ok");
    result.pushKV("proof", std::move(proof));
    return result;
}

template <typename Evaluator>
static UniValue BuildMatMulServiceBatchResult(
    const std::vector<MatMulServiceProofBatchItem>& items,
    Evaluator&& evaluator)
{
    UniValue results(UniValue::VARR);
    std::map<std::string, int> by_reason;
    int valid_count{0};

    for (size_t index = 0; index < items.size(); ++index) {
        try {
            UniValue result = evaluator(items[index]);
            const bool valid = result.find_value("valid").get_bool();
            if (valid) {
                ++valid_count;
            }
            const std::string reason = result.find_value("reason").get_str();
            ++by_reason[reason];
            result.pushKV("index", static_cast<uint64_t>(index));
            results.push_back(std::move(result));
        } catch (const UniValue& obj_error) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "proofs[%u].%s",
                    static_cast<unsigned>(index),
                    obj_error.find_value("message").get_str()));
        } catch (const std::exception& e) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("proofs[%u].%s", static_cast<unsigned>(index), e.what()));
        }
    }

    UniValue reason_counts(UniValue::VOBJ);
    for (const auto& [reason, count] : by_reason) {
        reason_counts.pushKV(reason, count);
    }

    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(items.size()));
    summary.pushKV("valid", valid_count);
    summary.pushKV("invalid", static_cast<int>(items.size()) - valid_count);
    summary.pushKV("by_reason", std::move(reason_counts));
    summary.pushKV("results", std::move(results));
    return summary;
}

static bool ShouldEnableMatMulTipWatcher()
{
    // Single-node bootstrap mining can disable this to remove per-block
    // watcher thread overhead. Keep enabled by default for safety.
    static const bool enabled = []() {
        const char* env = std::getenv("BTX_MATMUL_TIP_WATCHER");
        if (env == nullptr || env[0] == '\0') {
            return true;
        }
        return env[0] != '0';
    }();
    return enabled;
}

static RPCErrorCode MiningChainGuardRpcCode(const node::MiningChainGuardStatus& status)
{
    if (status.reason == "initial_block_download" ||
        status.reason == "local_tip_behind_peer_median") {
        return RPC_CLIENT_IN_INITIAL_DOWNLOAD;
    }
    if (status.reason == "network_inactive" ||
        status.reason == "insufficient_peer_consensus" ||
        status.reason == "peer_monitor_unavailable") {
        return RPC_CLIENT_NOT_CONNECTED;
    }
    return RPC_MISC_ERROR;
}

static void EnsureMiningChainGuardOrThrow(NodeContext& node)
{
    const auto status = node::GetMiningChainGuardStatus(node);
    if (!node::ShouldPauseMiningByChainGuard(status)) return;

    throw JSONRPCError(
        MiningChainGuardRpcCode(status),
        "mining paused by chain guard: " + node::DescribeMiningChainGuardStatus(status));
}

static UniValue MiningChainGuardToJSON(const node::MiningChainGuardStatus& status)
{
    UniValue chain_guard(UniValue::VOBJ);
    chain_guard.pushKV("enabled", status.enabled);
    chain_guard.pushKV("healthy", status.healthy);
    chain_guard.pushKV("should_pause_mining", node::ShouldPauseMiningByChainGuard(status));
    chain_guard.pushKV("recommended_action", node::GetMiningChainGuardRecommendedAction(status));
    chain_guard.pushKV("reason", status.reason);
    chain_guard.pushKV("local_tip", status.local_tip_height);
    chain_guard.pushKV("peer_count", status.peer_count);
    chain_guard.pushKV("median_peer_tip", status.median_peer_tip);
    chain_guard.pushKV("best_peer_tip", status.best_peer_tip);
    chain_guard.pushKV("near_tip_peers", status.near_tip_peers);
    return chain_guard;
}

static RPCHelpMan getnetworkhashps()
{
    return RPCHelpMan{"getnetworkhashps",
                "\nReturns the estimated network hashes per second based on the last n blocks.\n"
                "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
                "Pass in [height] to estimate the network speed at the time when a certain block was found.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Default{120}, "The number of previous blocks to calculate estimate from, or -1 for blocks since last difficulty change."},
                    {"height", RPCArg::Type::NUM, RPCArg::Default{-1}, "To estimate at the time of the given height."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Hashes per second estimated"},
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetNetworkHashPS(self.Arg<int>("nblocks"), self.Arg<int>("height"), chainman.ActiveChain());
},
    };
}

static bool GenerateBlock(ChainstateManager& chainman, CBlock&& block, uint64_t& max_tries, std::shared_ptr<const CBlock>& block_out, bool process_new_block, const NodeContext* node_context = nullptr)
{
    block_out.reset();
    block.hashMerkleRoot = BlockMerkleRoot(block);
    const auto& consensus = chainman.GetConsensus();

    int next_height{0};
    bool kawpow_active{false};
    bool matmul_active{consensus.fMatMulPOW};
    uint256 tip_hash_before_mining;
    {
        LOCK(chainman.GetMutex());
        const CBlockIndex* pindex_prev = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
        if (!pindex_prev) {
            LogDebug(BCLog::MINING, "GenerateBlock: previous block %s not found in block index\n",
                     block.hashPrevBlock.GetHex());
            throw JSONRPCError(RPC_INTERNAL_ERROR, "previous block not found in block index");
        }
        if (!TryGetNextBlockHeight(pindex_prev, next_height)) {
            LogDebug(BCLog::MINING, "GenerateBlock: next block height overflow at prev height %d\n",
                     pindex_prev->nHeight);
            throw JSONRPCError(RPC_INTERNAL_ERROR, "next block height overflow");
        }
        kawpow_active = consensus.fKAWPOW && next_height >= consensus.nKAWPOWHeight;
        tip_hash_before_mining = chainman.ActiveChain().Tip()->GetBlockHash();
        LogDebug(BCLog::MINING, "GenerateBlock: starting for height %d, prevhash=%s, tip=%s, matmul=%s, kawpow=%s, max_tries=%lu\n",
                 next_height, block.hashPrevBlock.GetHex(), tip_hash_before_mining.GetHex(),
                 matmul_active ? "true" : "false", kawpow_active ? "true" : "false",
                 max_tries);
    }

    std::atomic<bool> abort_mining{false};
    std::thread tip_watcher;
    bool aborted_by_chain_guard{false};
    std::string chain_guard_reason;
    const bool watch_chain_guard =
        matmul_active &&
        process_new_block &&
        node_context != nullptr &&
        node::GetMiningChainGuardOptions(*node_context).enabled;

    // Launch tip-change watcher for MatMul mining (which can take seconds per batch).
    // Also fires on shutdown since chainman.m_interrupt causes the tip check to exit.
    if (matmul_active && process_new_block &&
        (ShouldEnableMatMulTipWatcher() || watch_chain_guard)) {
        tip_watcher = std::thread([&chainman, &abort_mining, &tip_hash_before_mining,
                                   &aborted_by_chain_guard, &chain_guard_reason,
                                   watch_chain_guard, node_context]() {
            uint32_t chain_guard_poll_ticks{0};
            while (!abort_mining.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
                if (abort_mining.load(std::memory_order_relaxed)) return;
                if (chainman.m_interrupt) {
                    abort_mining.store(true, std::memory_order_relaxed);
                    return;
                }
                {
                    LOCK(chainman.GetMutex());
                    const CBlockIndex* tip = chainman.ActiveChain().Tip();
                    if (!tip || tip->GetBlockHash() != tip_hash_before_mining) {
                        LogDebug(BCLog::MINING, "GenerateBlock: tip changed during mining, signaling abort\n");
                        abort_mining.store(true, std::memory_order_relaxed);
                        return;
                    }
                }

                if (watch_chain_guard && ++chain_guard_poll_ticks >= 5) {
                    chain_guard_poll_ticks = 0;
                    const auto status = node::GetMiningChainGuardStatus(*node_context);
                    if (node::ShouldPauseMiningByChainGuard(status)) {
                        chain_guard_reason = node::DescribeMiningChainGuardStatus(status);
                        aborted_by_chain_guard = true;
                        LogWarning("GenerateBlock: pausing local mining due to chain guard: %s\n",
                                   chain_guard_reason);
                        abort_mining.store(true, std::memory_order_relaxed);
                        return;
                    }
                }
            }
        });
    }

    auto cleanup_watcher = [&]() {
        abort_mining.store(true, std::memory_order_relaxed);
        if (tip_watcher.joinable()) tip_watcher.join();
    };

    if (matmul_active) {
        if (block.matmul_dim == 0) {
            block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        }
        if (block.seed_a.IsNull()) block.seed_a = DeterministicMatMulSeed(block.hashPrevBlock, static_cast<uint32_t>(next_height), 0);
        if (block.seed_b.IsNull()) block.seed_b = DeterministicMatMulSeed(block.hashPrevBlock, static_cast<uint32_t>(next_height), 1);
        block.mix_hash.SetNull();

        const bool include_freivalds_payload =
            ShouldIncludeMatMulFreivaldsPayloadForMining(next_height, consensus);
        std::vector<uint32_t>* freivalds_payload_out = include_freivalds_payload ? &block.matrix_c_data : nullptr;

        if (!SolveMatMul(block, consensus, max_tries, next_height, &abort_mining, freivalds_payload_out)) {
            cleanup_watcher();
            if (aborted_by_chain_guard) {
                throw JSONRPCError(
                    MiningChainGuardRpcCode(node::GetMiningChainGuardStatus(*node_context)),
                    "mining paused by chain guard: " + chain_guard_reason);
            }
            if (max_tries == 0 || chainman.m_interrupt) return false;
            if (block.nNonce64 == std::numeric_limits<uint64_t>::max()) return true;
            return false;
        }
        // Keep the Freivalds product payload only once the network requires it
        // or once the transcript-binding upgrade makes the optional payload
        // path safe for honest miners again.
        if (include_freivalds_payload && block.matrix_c_data.empty()) {
            // Populate Freivalds' C' payload unless SolveMatMul already
            // generated it via CPU confirmation on the accepted candidate.
            PopulateFreivaldsPayload(block, consensus);
        } else if (!include_freivalds_payload) {
            block.matrix_c_data.clear();
        }
    } else if (kawpow_active) {
        if (consensus.fSkipKAWPOWValidation) {
            // Keep regtest generation fast; KAWPOW validity is bypassed there.
            if (max_tries == 0 || chainman.m_interrupt) return false;
            block.nNonce64 = 0;
            block.mix_hash.SetNull();
            --max_tries;
        } else {
            block.mix_hash.SetNull();
            if (!SolveKAWPOW(block, static_cast<uint32_t>(next_height), consensus, max_tries)) {
                if (max_tries == 0 || chainman.m_interrupt) return false;
                if (block.nNonce64 == std::numeric_limits<uint64_t>::max()) return true;
                return false;
            }
        }
    } else {
        while (max_tries > 0 && block.nNonce < std::numeric_limits<uint32_t>::max() && !CheckProofOfWork(block.GetHash(), block.nBits, consensus) && !chainman.m_interrupt) {
            ++block.nNonce;
            --max_tries;
        }
        if (max_tries == 0 || chainman.m_interrupt) {
            return false;
        }
        if (block.nNonce == std::numeric_limits<uint32_t>::max()) {
            return true;
        }
    }

    cleanup_watcher();

    block_out = std::make_shared<const CBlock>(std::move(block));
    LogDebug(BCLog::MINING, "GenerateBlock: mining completed, block hash=%s, process_new_block=%s\n",
             block_out->GetHash().GetHex(), process_new_block ? "true" : "false");

    if (!process_new_block) return true;

    // Verify the chain tip has not changed during the (potentially long) mining
    // loop. If the tip moved, the mined block is stale and ProcessNewBlock would
    // either reject it or, worse, hit an assertion in TestBlockValidity.
    {
        LOCK(chainman.GetMutex());
        const CBlockIndex* current_tip = chainman.ActiveChain().Tip();
        if (!current_tip || current_tip->GetBlockHash() != tip_hash_before_mining) {
            LogWarning("GenerateBlock: chain tip changed during mining (before=%s, now=%s); mined block is stale\n",
                       tip_hash_before_mining.GetHex(),
                       current_tip ? current_tip->GetBlockHash().GetHex() : "null");
            throw JSONRPCError(RPC_INTERNAL_ERROR, "chain tip changed during mining; mined block is stale");
        }
    }

    LogDebug(BCLog::MINING, "GenerateBlock: submitting block %s via ProcessNewBlock\n",
             block_out->GetHash().GetHex());
    if (!chainman.ProcessNewBlock(block_out, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr)) {
        LogWarning("GenerateBlock: ProcessNewBlock rejected block %s\n", block_out->GetHash().GetHex());
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
    }
    LogDebug(BCLog::MINING, "GenerateBlock: block %s accepted successfully\n", block_out->GetHash().GetHex());

    return true;
}

static bool IsP2MROutputScript(const CScript& script_pub_key)
{
    int witness_version{-1};
    std::vector<unsigned char> witness_program;
    if (!script_pub_key.IsWitnessProgram(witness_version, witness_program)) return false;
    return witness_version == 2 && witness_program.size() == 32;
}

static void CheckCoinbaseOutputScriptOrThrow(const Consensus::Params& consensus, const CScript& coinbase_output_script)
{
    if (!(consensus.fReducedDataLimits && consensus.fEnforceP2MROnlyOutputs)) return;

    const bool is_op_return{!coinbase_output_script.empty() && coinbase_output_script[0] == OP_RETURN};
    if (is_op_return) {
        if (coinbase_output_script.size() > consensus.nMaxOpReturnBytes) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Coinbase OP_RETURN output script exceeds reduced-data size limit");
        }
        return;
    }

    if (!IsP2MROutputScript(coinbase_output_script)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Coinbase output must be witness v2 P2MR (32-byte program) or OP_RETURN under reduced-data limits");
    }
}

static UniValue generateBlocks(ChainstateManager& chainman, Mining& miner, const CScript& coinbase_output_script, int nGenerate, uint64_t nMaxTries)
{
    CheckCoinbaseOutputScriptOrThrow(chainman.GetParams().GetConsensus(), coinbase_output_script);
    NodeContext* node_context = miner.context();

    UniValue blockHashes(UniValue::VARR);
    while (nGenerate > 0 && !chainman.m_interrupt) {
        if (node_context) EnsureMiningChainGuardOrThrow(*node_context);
        std::unique_ptr<BlockTemplate> block_template(miner.createNewBlock({ .coinbase_output_script = coinbase_output_script }));
        CHECK_NONFATAL(block_template);

        std::shared_ptr<const CBlock> block_out;
        if (!GenerateBlock(chainman, CBlock{block_template->getBlock()}, nMaxTries, block_out, /*process_new_block=*/true, node_context)) {
            break;
        }

        if (block_out) {
            --nGenerate;
            blockHashes.push_back(block_out->GetHash().GetHex());
        }
    }
    return blockHashes;
}

static bool getScriptFromDescriptor(const std::string& descriptor, CScript& script, std::string& error)
{
    FlatSigningProvider key_provider;
    const auto descs = Parse(descriptor, key_provider, error, /* require_checksum = */ false);
    if (descs.empty()) return false;
    if (descs.size() > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptor not accepted");
    }
    const auto& desc = descs.at(0);
    if (desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?");
    }

    FlatSigningProvider provider;
    std::vector<CScript> scripts;
    if (!desc->Expand(0, key_provider, scripts, provider)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive script without private keys");
    }

    // Combo descriptors can have 2 or 4 scripts, so we can't just check scripts.size() == 1
    CHECK_NONFATAL(scripts.size() > 0 && scripts.size() <= 4);

    if (scripts.size() == 1) {
        script = scripts.at(0);
    } else if (scripts.size() == 4) {
        // For uncompressed keys, take the 3rd script, since it is p2wpkh
        script = scripts.at(2);
    } else {
        // Else take the 2nd script, since it is p2pkh
        script = scripts.at(1);
    }

    return true;
}

static RPCHelpMan generatetodescriptor()
{
    return RPCHelpMan{
        "generatetodescriptor",
        "Mine to a specified descriptor and return the block hashes.",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor to send the newly generated BTX to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "hashes of blocks generated",
            {
                {RPCResult::Type::STR_HEX, "", "blockhash"},
            }
        },
        RPCExamples{
            "\nGenerate 11 blocks to mydesc\n" + HelpExampleCli("generatetodescriptor", "11 \"mydesc\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto num_blocks{self.Arg<int>("num_blocks")};
    const auto max_tries{self.Arg<uint64_t>("maxtries")};

    CScript coinbase_output_script;
    std::string error;
    if (!getScriptFromDescriptor(self.Arg<std::string>("descriptor"), coinbase_output_script, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    ChainstateManager& chainman = EnsureChainman(node);

    return generateBlocks(chainman, miner, coinbase_output_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generate()
{
    return RPCHelpMan{"generate", "has been replaced by the -generate cli option. Refer to -help for more information.", {}, {}, RPCExamples{""}, [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, self.ToString());
    }};
}

static RPCHelpMan generatetoaddress()
{
    return RPCHelpMan{"generatetoaddress",
        "Mine to a specified address and return the block hashes.",
         {
             {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
             {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated BTX to."},
             {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
         },
         RPCResult{
             RPCResult::Type::ARR, "", "hashes of blocks generated",
             {
                 {RPCResult::Type::STR_HEX, "", "blockhash"},
             }},
         RPCExamples{
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
            + "If you are using the " CLIENT_NAME " wallet, you can get a new address to send the newly generated BTX to with:\n"
            + HelpExampleCli("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int num_blocks{request.params[0].getInt<int>()};
    const uint64_t max_tries{request.params[2].isNull() ? DEFAULT_MAX_TRIES : request.params[2].getInt<uint64_t>()};

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    ChainstateManager& chainman = EnsureChainman(node);

    CScript coinbase_output_script = GetScriptForDestination(destination);

    return generateBlocks(chainman, miner, coinbase_output_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generateblock()
{
    return RPCHelpMan{"generateblock",
        "Mine a set of ordered transactions to a specified address or descriptor and return the block hash.",
        {
            {"output", RPCArg::Type::STR, RPCArg::Optional::NO, "The address or descriptor to send the newly generated BTX to."},
            {"transactions", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of hex strings which are either txids or raw transactions.\n"
                "Txids must reference transactions currently in the mempool.\n"
                "All transactions must be valid and in valid order, otherwise the block will be rejected.",
                {
                    {"rawtx/txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"submit", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to submit the block before the RPC call returns or to return it as hex."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "hash of generated block"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "hex of generated block, only present when submit=false"},
            }
        },
        RPCExamples{
            "\nGenerate a block to myaddress, with txs rawtx and mempool_txid\n"
            + HelpExampleCli("generateblock", R"("myaddress" '["rawtx", "mempool_txid"]')")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto address_or_descriptor = request.params[0].get_str();
    CScript coinbase_output_script;
    std::string error;

    if (!getScriptFromDescriptor(address_or_descriptor, coinbase_output_script, error)) {
        const auto destination = DecodeDestination(address_or_descriptor);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address or descriptor");
        }

        coinbase_output_script = GetScriptForDestination(destination);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    const CTxMemPool& mempool = EnsureMemPool(node);
    EnsureMiningChainGuardOrThrow(node);

    std::vector<CTransactionRef> txs;
    const auto raw_txs_or_txids = request.params[1].get_array();
    for (size_t i = 0; i < raw_txs_or_txids.size(); i++) {
        const auto& str{raw_txs_or_txids[i].get_str()};

        CMutableTransaction mtx;
        if (auto hash{uint256::FromHex(str)}) {
            const auto tx{mempool.get(*hash)};
            if (!tx) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Transaction %s not in mempool.", str));
            }

            txs.emplace_back(tx);

        } else if (DecodeHexTx(mtx, str)) {
            txs.push_back(MakeTransactionRef(std::move(mtx)));

        } else {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Transaction decode failed for %s. Make sure the tx has at least one input.", str));
        }
    }

    const bool process_new_block{request.params[2].isNull() ? true : request.params[2].get_bool()};
    CBlock block;

    ChainstateManager& chainman = EnsureChainman(node);
    CheckCoinbaseOutputScriptOrThrow(chainman.GetParams().GetConsensus(), coinbase_output_script);
    {
        LOCK(chainman.GetMutex());
        {
            std::unique_ptr<BlockTemplate> block_template{miner.createNewBlock({.use_mempool = false, .coinbase_output_script = coinbase_output_script})};
            CHECK_NONFATAL(block_template);

            block = block_template->getBlock();
        }

        CHECK_NONFATAL(block.vtx.size() == 1);

        // Add transactions
        block.vtx.insert(block.vtx.end(), txs.begin(), txs.end());
        RegenerateCommitments(block, chainman);

        CBlockIndex* pindex_prev{chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock)};
        if (!pindex_prev) {
            LogWarning("generateblock: previous block index not found for hashPrevBlock=%s\n",
                       block.hashPrevBlock.GetHex());
            throw JSONRPCError(RPC_INTERNAL_ERROR, "previous block index not found for generateblock");
        }
        if (pindex_prev != chainman.ActiveChain().Tip()) {
            LogWarning("generateblock: pindex_prev (height=%d, hash=%s) is not the current chain tip (hash=%s)\n",
                       pindex_prev->nHeight, pindex_prev->GetBlockHash().GetHex(),
                       chainman.ActiveChain().Tip() ? chainman.ActiveChain().Tip()->GetBlockHash().GetHex() : "null");
            throw JSONRPCError(RPC_INTERNAL_ERROR, "previous block is not the current chain tip");
        }
        int next_height{0};
        if (!TryGetNextBlockHeight(pindex_prev, next_height)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "next block height overflow");
        }
        LogDebug(BCLog::MINING, "generateblock: building block at height %d, prev=%s, ntx=%zu\n",
                 next_height, pindex_prev->GetBlockHash().GetHex(), block.vtx.size());
        const auto& consensus = chainman.GetConsensus();
        const bool skip_pow_template_check =
            consensus.fMatMulPOW ||
            (consensus.fKAWPOW && !consensus.fSkipKAWPOWValidation &&
                next_height >= consensus.nKAWPOWHeight);

        BlockValidationState state;
        if (!skip_pow_template_check) {
            LogDebug(BCLog::MINING, "generateblock: running TestBlockValidity for height %d\n", next_height);
            if (!TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block, pindex_prev, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
                LogWarning("generateblock: TestBlockValidity failed at height %d: %s\n", next_height, state.ToString());
                throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("TestBlockValidity failed: %s", state.ToString()));
            }
            LogDebug(BCLog::MINING, "generateblock: TestBlockValidity passed for height %d\n", next_height);
        } else {
            LogDebug(BCLog::MINING, "generateblock: skipping TestBlockValidity (skip_pow_template_check=true) for height %d\n", next_height);
        }
    }

    std::shared_ptr<const CBlock> block_out;
    uint64_t max_tries{DEFAULT_MAX_TRIES};

    if (!GenerateBlock(chainman, std::move(block), max_tries, block_out, process_new_block, &node) || !block_out) {
        LogWarning("generateblock: GenerateBlock failed or returned no block\n");
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to make block.");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("hash", block_out->GetHash().GetHex());
    if (!process_new_block) {
        DataStream block_ser;
        block_ser << TX_WITH_WITNESS(*block_out);
        obj.pushKV("hex", HexStr(block_ser));
    }
    return obj;
},
    };
}

static RPCHelpMan getmininginfo()
{
    return RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "currentblocksize", /*optional=*/true, "The block size (including reserved weight for block header, txs count and coinbase tx) of the last assembled block (only present if a block was ever assembled, and blockmaxsize is configured)"},
                        {RPCResult::Type::NUM, "currentblockweight", /*optional=*/true, "The block weight (including reserved weight for block header, txs count and coinbase tx) of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblocktx", /*optional=*/true, "The number of block transactions (excluding coinbase) of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblockshieldedverifyunits", /*optional=*/true, "The shielded verification units in the last assembled block template (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblockshieldedscanunits", /*optional=*/true, "The shielded scan units in the last assembled block template (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblockshieldedtreeupdateunits", /*optional=*/true, "The shielded tree-update units in the last assembled block template (only present if a block was ever assembled)"},
                        {RPCResult::Type::STR_HEX, "bits", "The current nBits, compact representation of the block difficulty target"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::STR_HEX, "target", "The current target"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (" LIST_CHAIN_NAMES ")"},
                        {RPCResult::Type::STR, "algorithm", "current proof-of-work algorithm (alias of powalgorithm)"},
                        {RPCResult::Type::STR, "powalgorithm", "current proof-of-work algorithm"},
                        {RPCResult::Type::NUM, "max_block_weight", "consensus maximum block weight"},
                        {RPCResult::Type::NUM, "policy_block_max_weight", "effective local block template weight target"},
                        {RPCResult::Type::NUM, "max_block_shielded_verify_units", "consensus maximum shielded verification units per block"},
                        {RPCResult::Type::NUM, "max_block_shielded_scan_units", "consensus maximum shielded scan units per block"},
                        {RPCResult::Type::NUM, "max_block_shielded_tree_update_units", "consensus maximum shielded tree-update units per block"},
                        {RPCResult::Type::NUM, "matmul_n", /*optional=*/true, "MatMul matrix dimension (n)"},
                        {RPCResult::Type::NUM, "matmul_b", /*optional=*/true, "MatMul transcript block size (b)"},
                        {RPCResult::Type::NUM, "matmul_r", /*optional=*/true, "MatMul noise rank (r)"},
                        {RPCResult::Type::OBJ, "chain_guard", "Local mining chain-alignment guard status",
                        {
                            {RPCResult::Type::BOOL, "enabled", "Whether the guard is enabled on this node"},
                            {RPCResult::Type::BOOL, "healthy", "Whether local mining is currently allowed to continue"},
                            {RPCResult::Type::BOOL, "should_pause_mining", "Whether miners should currently stop submitting new work to this node"},
                            {RPCResult::Type::STR, "recommended_action", "Recommended miner action: continue, catch_up, or pause"},
                            {RPCResult::Type::STR, "reason", "Current guard decision reason"},
                            {RPCResult::Type::NUM, "local_tip", "Current local active-chain height"},
                            {RPCResult::Type::NUM, "peer_count", "Outbound peers considered for the guard decision"},
                            {RPCResult::Type::NUM, "median_peer_tip", "Median tip height advertised by considered outbound peers, or -1 if unavailable"},
                            {RPCResult::Type::NUM, "best_peer_tip", "Highest tip height advertised by considered outbound peers, or -1 if unavailable"},
                            {RPCResult::Type::NUM, "near_tip_peers", "Considered outbound peers within the near-tip window of the local tip"},
                        }},
                        {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "The block challenge (aka. block script), in hexadecimal (only present if the current network is a signet)"},
                        {RPCResult::Type::OBJ, "next", "The next block",
                        {
                            {RPCResult::Type::NUM, "height", "The next height"},
                            {RPCResult::Type::STR_HEX, "bits", "The next target nBits"},
                            {RPCResult::Type::NUM, "difficulty", "The next difficulty"},
                            {RPCResult::Type::STR_HEX, "target", "The next target"}
                        }},
                        (IsDeprecatedRPCEnabled("warnings") ?
                            RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
                            RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)",
                            {
                                {RPCResult::Type::STR, "", "warning"},
                            }
                            }
                        ),
                    }},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);
    BlockAssembler::Options block_options;
    const auto chain_guard_status = node::GetMiningChainGuardStatus(node);
    {
        const ArgsManager& args{EnsureAnyArgsman(request.context)};
        ApplyArgsManOptions(args, block_options);
    }
    const BlockAssembler::Options block_options_clamped{block_options.Clamped()};
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();
    CBlockIndex& tip{*CHECK_NONFATAL(active_chain.Tip())};

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           active_chain.Height());
    if (BlockAssembler::m_last_block_size) obj.pushKV("currentblocksize", *BlockAssembler::m_last_block_size);
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    if (BlockAssembler::m_last_block_shielded_verify_units) obj.pushKV("currentblockshieldedverifyunits", *BlockAssembler::m_last_block_shielded_verify_units);
    if (BlockAssembler::m_last_block_shielded_scan_units) obj.pushKV("currentblockshieldedscanunits", *BlockAssembler::m_last_block_shielded_scan_units);
    if (BlockAssembler::m_last_block_shielded_tree_update_units) obj.pushKV("currentblockshieldedtreeupdateunits", *BlockAssembler::m_last_block_shielded_tree_update_units);
    obj.pushKV("bits", strprintf("%08x", tip.nBits));
    obj.pushKV("difficulty", GetDifficulty(tip));
    obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("networkhashps",    getnetworkhashps().HandleRequest(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    const std::string algorithm =
        chainman.GetConsensus().fMatMulPOW ? "matmul" :
        (chainman.GetConsensus().fKAWPOW ? "kawpow" : "sha256d");
    obj.pushKV("algorithm", algorithm);
    obj.pushKV("powalgorithm", algorithm);
    obj.pushKV("max_block_weight", static_cast<int64_t>(MAX_BLOCK_WEIGHT));
    obj.pushKV("policy_block_max_weight", static_cast<int64_t>(block_options_clamped.nBlockMaxWeight));
    obj.pushKV("max_block_shielded_verify_units", static_cast<int64_t>(chainman.GetConsensus().nMaxBlockShieldedVerifyCost));
    obj.pushKV("max_block_shielded_scan_units", static_cast<int64_t>(chainman.GetConsensus().nMaxBlockShieldedScanUnits));
    obj.pushKV("max_block_shielded_tree_update_units", static_cast<int64_t>(chainman.GetConsensus().nMaxBlockShieldedTreeUpdateUnits));
    if (chainman.GetConsensus().fMatMulPOW) {
        obj.pushKV("matmul_n", static_cast<int64_t>(chainman.GetConsensus().nMatMulDimension));
        obj.pushKV("matmul_b", static_cast<int64_t>(chainman.GetConsensus().nMatMulTranscriptBlockSize));
        obj.pushKV("matmul_r", static_cast<int64_t>(chainman.GetConsensus().nMatMulNoiseRank));
    }
    obj.pushKV("chain_guard", MiningChainGuardToJSON(chain_guard_status));

    UniValue next(UniValue::VOBJ);
    CBlockIndex next_index;
    NextEmptyBlockIndex(tip, chainman.GetConsensus(), next_index);

    next.pushKV("height", next_index.nHeight);
    next.pushKV("bits", strprintf("%08x", next_index.nBits));
    next.pushKV("difficulty", GetDifficulty(next_index));
    next.pushKV("target", GetTarget(next_index, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("next", next);

    if (chainman.GetParams().GetChainType() == ChainType::SIGNET) {
        const std::vector<uint8_t>& signet_challenge =
            chainman.GetConsensus().signet_challenge;
        obj.pushKV("signet_challenge", HexStr(signet_challenge));
    }
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings), IsDeprecatedRPCEnabled("warnings")));
    return obj;
},
    };
}

static RPCHelpMan getdifficultyhealth()
{
    return RPCHelpMan{"getdifficultyhealth",
                "\nReturns difficulty-health metadata for the active chain over a recent block window.\n",
                {
                    {"window_blocks", RPCArg::Type::NUM, RPCArg::Default{120}, "Recent block window to summarize"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "chain", "Current network name"},
                        {RPCResult::Type::STR, "algorithm", "Current proof-of-work algorithm"},
                        {RPCResult::Type::NUM, "window_blocks", "Recent block window used for interval statistics"},
                        {RPCResult::Type::NUM, "target_spacing_s", "Consensus target spacing in seconds"},
                        {RPCResult::Type::OBJ, "tip", "",
                        {
                            {RPCResult::Type::NUM, "height", "Current chain height"},
                            {RPCResult::Type::STR_HEX, "hash", "Current tip hash"},
                            {RPCResult::Type::NUM, "time", "Current tip time"},
                            {RPCResult::Type::STR_HEX, "bits", "Current compact target"},
                            {RPCResult::Type::NUM, "difficulty", "Current difficulty"},
                            {RPCResult::Type::STR_HEX, "target", "Current target"},
                        }},
                        {RPCResult::Type::OBJ, "next", "",
                        {
                            {RPCResult::Type::NUM, "height", "Next height"},
                            {RPCResult::Type::STR_HEX, "bits", "Next compact target"},
                            {RPCResult::Type::NUM, "difficulty", "Next difficulty"},
                            {RPCResult::Type::STR_HEX, "target", "Next target"},
                        }},
                        {RPCResult::Type::OBJ, "recent", "",
                        {
                            {RPCResult::Type::NUM, "count", "Intervals included in the summary"},
                            {RPCResult::Type::NUM, "mean_interval_s", "Mean interval in seconds"},
                            {RPCResult::Type::NUM, "p50_interval_s", "Median interval in seconds"},
                            {RPCResult::Type::NUM, "p90_interval_s", "p90 interval in seconds"},
                            {RPCResult::Type::NUM, "p99_interval_s", "p99 interval in seconds"},
                            {RPCResult::Type::NUM, "stddev_interval_s", "Population standard deviation"},
                            {RPCResult::Type::NUM, "mean_abs_error_s", "Mean absolute error versus target spacing"},
                            {RPCResult::Type::NUM, "max_overshoot_s", "Largest interval overshoot versus target spacing"},
                            {RPCResult::Type::NUM, "max_undershoot_s", "Largest interval undershoot versus target spacing"},
                        }},
                        {RPCResult::Type::OBJ, "network", "", {
                            {RPCResult::Type::BOOL, "network_active", "Whether P2P networking is active"},
                            {RPCResult::Type::NUM, "connected_peers", "Total connected peers"},
                            {RPCResult::Type::NUM, "outbound_peers", "Connected outbound peers"},
                            {RPCResult::Type::NUM, "synced_outbound_peers", "Outbound peers within the configured sync-height lag"},
                            {RPCResult::Type::NUM, "manual_outbound_peers", "Outbound peers opened with manual connection policy"},
                            {RPCResult::Type::NUM, "outbound_peers_missing_sync_height", "Outbound peers lacking a reported sync height from net_processing state"},
                            {RPCResult::Type::NUM, "outbound_peers_beyond_sync_lag", "Outbound peers whose reported sync height exceeds the configured lag threshold"},
                            {RPCResult::Type::NUM, "recent_block_announcing_outbound_peers", "Outbound peers that have announced at least one block since this process started"},
                            {RPCResult::Type::NUM, "validated_tip_height", "Current validated tip height"},
                            {RPCResult::Type::NUM, "best_header_height", "Best known header height"},
                            {RPCResult::Type::NUM, "header_lag", "Best header height minus validated tip height"},
                            {RPCResult::Type::NUM, "required_outbound_peers", "Configured outbound peer guard for mining readiness"},
                            {RPCResult::Type::NUM, "required_synced_outbound_peers", "Configured synced outbound peer guard for mining readiness"},
                            {RPCResult::Type::NUM, "max_peer_sync_height_lag", "Configured peer sync-height lag guard"},
                            {RPCResult::Type::NUM, "max_header_lag", "Configured validated-tip header lag guard"},
                            {RPCResult::Type::ARR, "outbound_peer_diagnostics", "Per-peer outbound readiness diagnostics", {
                                {RPCResult::Type::OBJ, "", "", {
                                    {RPCResult::Type::STR, "addr", "Peer address or label"},
                                    {RPCResult::Type::STR, "connection_type", "Peer connection type"},
                                    {RPCResult::Type::BOOL, "manual", "Whether the peer is a manual connection"},
                                    {RPCResult::Type::NUM, "sync_height", "Best known validated block height reported for the peer, or -1 if unavailable"},
                                    {RPCResult::Type::NUM, "common_height", "Best last-common-block height reported for the peer, or -1 if unavailable"},
                                    {RPCResult::Type::NUM, "presync_height", "Presync header height reported for the peer, or -1 if unavailable"},
                                    {RPCResult::Type::NUM, "starting_height", "Peer starting height from version handshake"},
                                    {RPCResult::Type::NUM, "sync_lag", "Local validated tip height minus peer sync height, or -1 if unavailable"},
                                    {RPCResult::Type::NUM, "last_block_time", "Unix timestamp of the last block relay observed on the connection"},
                                    {RPCResult::Type::NUM, "last_block_announcement", "Unix timestamp of the last block announcement attributed to the peer"},
                                    {RPCResult::Type::BOOL, "counts_as_synced_outbound", "Whether this peer satisfies the synced-outbound readiness rule"},
                                }},
                            }},
                        }},
                        {RPCResult::Type::OBJ, "reorg_protection", "", {
                            {RPCResult::Type::BOOL, "enabled", "Whether explicit deep-reorg protection is configured"},
                            {RPCResult::Type::BOOL, "active", "Whether the chain tip is at or above the protection activation height"},
                            {RPCResult::Type::NUM, "current_tip_height", "Current active tip height used for activation checks"},
                            {RPCResult::Type::NUM, "start_height", "Configured activation height for deep-reorg protection"},
                            {RPCResult::Type::NUM, "max_reorg_depth", "Configured maximum permitted reorganization depth"},
                            {RPCResult::Type::NUM, "rejected_reorgs", "Rejected deep reorgs recorded since process start"},
                            {RPCResult::Type::NUM, "deepest_rejected_reorg_depth", "Deepest rejected reorg observed since process start"},
                            {RPCResult::Type::NUM, "last_rejected_reorg_depth", "Depth of the most recent rejected reorg"},
                            {RPCResult::Type::NUM, "last_rejected_max_reorg_depth", "Configured max depth in effect for the most recent rejection"},
                            {RPCResult::Type::NUM, "last_rejected_tip_height", "Active tip height when the most recent rejection occurred"},
                            {RPCResult::Type::NUM, "last_rejected_fork_height", "Fork point height for the most recent rejection"},
                            {RPCResult::Type::NUM, "last_rejected_candidate_height", "Candidate chain height for the most recent rejection"},
                            {RPCResult::Type::NUM, "last_rejected_unix", "Unix timestamp of the most recent rejected reorg"},
                        }},
                        {RPCResult::Type::OBJ, "consensus_guards", "", {
                            {RPCResult::Type::OBJ, "freivalds_transcript_binding", "", {
                                {RPCResult::Type::BOOL, "active", "Whether Freivalds blocks must also pass transcript recomputation"},
                                {RPCResult::Type::NUM, "activation_height", "Activation height for transcript binding, or -1 if disabled"},
                                {RPCResult::Type::NUM, "remaining_blocks", "Blocks remaining until transcript binding activates"},
                            }},
                            {RPCResult::Type::OBJ, "freivalds_payload_mining", "", {
                                {RPCResult::Type::BOOL, "enabled", "Whether this node will include Freivalds product payloads in newly mined blocks"},
                                {RPCResult::Type::BOOL, "required_by_consensus", "Whether newly mined blocks must carry Freivalds product payloads for consensus validity"},
                                {RPCResult::Type::NUM, "activation_height", "Height at which optional payload mining becomes enabled by the transcript-binding upgrade, or -1 if disabled"},
                                {RPCResult::Type::NUM, "remaining_blocks", "Blocks remaining until optional payload mining becomes enabled"},
                            }},
                            {RPCResult::Type::OBJ, "asert_half_life", "", {
                                {RPCResult::Type::NUM, "current_s", "Currently active ASERT half-life in seconds for the active tip regime"},
                                {RPCResult::Type::NUM, "current_anchor_height", "Anchor height for the active ASERT regime"},
                                {RPCResult::Type::BOOL, "upgrade_active", "Whether the scheduled future ASERT half-life upgrade is already active"},
                                {RPCResult::Type::NUM, "upgrade_height", "Activation height for the scheduled half-life upgrade, or -1 if none is configured"},
                                {RPCResult::Type::NUM, "upgrade_half_life_s", "Half-life that will become active at the scheduled upgrade height, or the current half-life if none is configured"},
                                {RPCResult::Type::NUM, "remaining_blocks", "Blocks remaining until the scheduled half-life upgrade becomes active"},
                            }},
                            {RPCResult::Type::OBJ, "pre_hash_epsilon_bits", "", {
                                {RPCResult::Type::NUM, "current_bits", "Currently active MatMul pre-hash epsilon bits for the active tip regime"},
                                {RPCResult::Type::NUM, "next_block_bits", "MatMul pre-hash epsilon bits that will apply to the next candidate block"},
                                {RPCResult::Type::BOOL, "upgrade_active", "Whether the scheduled future MatMul pre-hash epsilon upgrade is already active"},
                                {RPCResult::Type::NUM, "upgrade_height", "Activation height for the scheduled pre-hash epsilon upgrade, or -1 if none is configured"},
                                {RPCResult::Type::NUM, "upgrade_bits", "Pre-hash epsilon bits that will become active at the scheduled upgrade height, or the current value if none is configured"},
                                {RPCResult::Type::NUM, "remaining_blocks", "Blocks remaining until the scheduled pre-hash epsilon upgrade becomes active"},
                            }},
                        }},
                        {RPCResult::Type::OBJ, "reward_distribution", "", {
                            {RPCResult::Type::NUM, "count", "Blocks included in the reward-distribution window"},
                            {RPCResult::Type::NUM, "unique_recipients", "Unique coinbase recipients observed in the window"},
                            {RPCResult::Type::NUM, "unknown_recipients", "Coinbase payouts that could not be encoded as addresses"},
                            {RPCResult::Type::NUM, "top_share", "Largest recipient block share in the window"},
                            {RPCResult::Type::NUM, "top3_share", "Combined block share of the top three recipients"},
                            {RPCResult::Type::NUM, "hhi", "Herfindahl-Hirschman concentration index across block shares"},
                            {RPCResult::Type::NUM, "gini", "Gini coefficient across block shares"},
                            {RPCResult::Type::NUM, "total_reward_sats", "Total coinbase value paid across the window in satoshis"},
                            {RPCResult::Type::OBJ, "longest_streak", "Longest consecutive block-winning streak in the window", {
                                {RPCResult::Type::STR, "recipient", "Encoded payout address or script label"},
                                {RPCResult::Type::NUM, "blocks", "Consecutive blocks won in the streak"},
                                {RPCResult::Type::NUM, "start_height", "Height of the first block in the streak"},
                                {RPCResult::Type::NUM, "end_height", "Height of the last block in the streak"},
                                {RPCResult::Type::NUM, "block_share", "Streak length divided by window block count"},
                                {RPCResult::Type::NUM, "recipient_share", "Overall block share of the streak recipient within the full window"},
                                {RPCResult::Type::NUM, "probability_at_least_observed", "Exact probability of seeing a streak at least this long in a stationary Bernoulli process with the recipient's observed share"},
                                {RPCResult::Type::NUM, "probability_upper_bound", "Union-bound upper limit for the streak probability"},
                                {RPCResult::Type::NUM, "log10_probability_upper_bound", "Base-10 logarithm of the upper-bound streak probability"},
                                {RPCResult::Type::BOOL, "statistically_improbable", "Whether the streak probability falls below the extreme-improbability threshold"},
                                {RPCResult::Type::NUM, "context_window_blocks", "Local context window used to test whether the streak happened during a temporarily dominant mining-share epoch"},
                                {RPCResult::Type::NUM, "context_start_height", "Height of the first block in the local streak-context window"},
                                {RPCResult::Type::NUM, "context_end_height", "Height of the last block in the local streak-context window"},
                                {RPCResult::Type::NUM, "context_recipient_share", "Recipient share within the local streak-context window"},
                                {RPCResult::Type::NUM, "context_unique_recipients", "Unique payout recipients seen inside the local streak-context window"},
                                {RPCResult::Type::NUM, "context_mean_interval_s", "Mean block interval inside the local streak-context window"},
                                {RPCResult::Type::BOOL, "nonstationary_share_suspected", "Whether the local context suggests the streak occurred during a nonstationary mining-share epoch rather than under the window-wide stationary share"},
                            }},
                            {RPCResult::Type::ARR, "top_recipients", "Top recipients by block count", {
                                {RPCResult::Type::OBJ, "", "", {
                                    {RPCResult::Type::STR, "recipient", "Encoded payout address or script label"},
                                    {RPCResult::Type::NUM, "blocks", "Blocks won by this recipient"},
                                    {RPCResult::Type::NUM, "block_share", "Recipient block share in the window"},
                                    {RPCResult::Type::NUM, "reward_sats", "Coinbase value paid to this recipient in satoshis"},
                                    {RPCResult::Type::NUM, "reward_share", "Recipient share of total reward value in the window"},
                                }},
                            }},
                        }},
                        {RPCResult::Type::OBJ, "service_challenge_registry", "", {
                            {RPCResult::Type::STR, "status", "Registry health code"},
                            {RPCResult::Type::BOOL, "healthy", "Whether the registry is currently healthy"},
                            {RPCResult::Type::BOOL, "shared", "Whether the registry path is configured as a shared file"},
                            {RPCResult::Type::STR, "path", "Registry path for this node"},
                            {RPCResult::Type::NUM, "entries", "Currently loaded registry entries"},
                            {RPCResult::Type::NUM, "last_checked_at", "Unix timestamp of the last registry load/persist observation"},
                            {RPCResult::Type::NUM, "last_success_at", /*optional=*/true, "Unix timestamp of the most recent successful registry load/persist"},
                            {RPCResult::Type::NUM, "last_failure_at", /*optional=*/true, "Unix timestamp of the most recent registry failure"},
                            {RPCResult::Type::STR, "quarantine_path", /*optional=*/true, "Quarantine path created after a corrupt/unsupported registry was isolated"},
                            {RPCResult::Type::STR, "error", /*optional=*/true, "Most recent registry failure detail"},
                        }},
                        {RPCResult::Type::NUM, "networkhashps", "Estimated network hashes per second for the same window"},
                        {RPCResult::Type::NUM, "health_score", "Summary health score in [0, 100]"},
                        {RPCResult::Type::ARR, "alerts", "Threshold alerts for the recent window", {
                            {RPCResult::Type::STR, "", "Alert string"},
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("getdifficultyhealth", "")
            + HelpExampleCli("getdifficultyhealth", "240")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int window_blocks = self.Arg<int>("window_blocks");
    if (window_blocks <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "window_blocks must be positive");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const ArgsManager& args = EnsureArgsman(node);
    const auto registry_health = GetMatMulServiceChallengeRegistryHealthSnapshot(args);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();
    CBlockIndex& tip{*CHECK_NONFATAL(active_chain.Tip())};
    CBlockIndex next_index;
    NextEmptyBlockIndex(tip, chainman.GetConsensus(), next_index);

    const IntervalHealthStats stats = ComputeRecentIntervalStats(
        active_chain,
        window_blocks,
        static_cast<double>(chainman.GetConsensus().nPowTargetSpacing));
    const RewardDistributionStats reward_distribution =
        ComputeRecentRewardDistribution(chainman, active_chain, window_blocks);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("algorithm", PowAlgorithmName(chainman.GetConsensus()));
    obj.pushKV("window_blocks", window_blocks);
    obj.pushKV("target_spacing_s", static_cast<int64_t>(chainman.GetConsensus().nPowTargetSpacing));

    UniValue tip_obj(UniValue::VOBJ);
    tip_obj.pushKV("height", tip.nHeight);
    tip_obj.pushKV("hash", tip.GetBlockHash().GetHex());
    tip_obj.pushKV("time", tip.GetBlockTime());
    tip_obj.pushKV("bits", strprintf("%08x", tip.nBits));
    tip_obj.pushKV("difficulty", GetDifficulty(tip));
    tip_obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("tip", std::move(tip_obj));

    UniValue next_obj(UniValue::VOBJ);
    next_obj.pushKV("height", next_index.nHeight);
    next_obj.pushKV("bits", strprintf("%08x", next_index.nBits));
    next_obj.pushKV("difficulty", GetDifficulty(next_index));
    next_obj.pushKV("target", GetTarget(next_index, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("next", std::move(next_obj));
    obj.pushKV("recent", IntervalStatsToUniValue(stats));
    obj.pushKV("network", BuildPropagationProxyProfile(chainman, node));
    obj.pushKV("reorg_protection", BuildReorgProtectionProfile(chainman));
    obj.pushKV("consensus_guards", BuildConsensusGuardProfile(active_chain, chainman.GetConsensus()));
    obj.pushKV("reward_distribution", RewardDistributionToUniValue(reward_distribution));
    obj.pushKV("service_challenge_registry", MatMulServiceChallengeRegistryHealthToUniValue(registry_health));
    obj.pushKV("networkhashps", GetNetworkHashPS(window_blocks, -1, active_chain));
    obj.pushKV("health_score", DifficultyHealthScore(stats));
    UniValue alerts = DifficultyAlerts(stats);
    UniValue guard_alerts = ConsensusGuardAlerts(active_chain, chainman.GetConsensus());
    for (size_t index = 0; index < guard_alerts.size(); ++index) {
        alerts.push_back(guard_alerts[index].get_str());
    }
    UniValue reward_alerts = RewardDistributionAlerts(reward_distribution);
    for (size_t index = 0; index < reward_alerts.size(); ++index) {
        alerts.push_back(reward_alerts[index].get_str());
    }
    obj.pushKV("alerts", std::move(alerts));
    return obj;
},
    };
}

static RPCHelpMan getmatmulchallenge()
{
    return RPCHelpMan{"getmatmulchallenge",
                "\nReturns the next MatMul challenge snapshot derived from active chain state.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "chain", "Current network name"},
                        {RPCResult::Type::STR, "algorithm", "Proof-of-work algorithm"},
                        {RPCResult::Type::NUM, "height", "Next height"},
                        {RPCResult::Type::STR_HEX, "previousblockhash", "Current tip hash"},
                        {RPCResult::Type::NUM, "mintime", "Minimum block time for the next block"},
                        {RPCResult::Type::STR_HEX, "bits", "Compact target"},
                        {RPCResult::Type::NUM, "difficulty", "Difficulty"},
                        {RPCResult::Type::STR_HEX, "target", "Target"},
                        {RPCResult::Type::STR, "noncerange", "Nonce search range"},
                        {RPCResult::Type::OBJ, "header_context", "Exact block-header fields used for sigma derivation before nonce scanning", {
                            {RPCResult::Type::NUM, "version", "Block version used in the challenge header"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", "Previous block hash used in the challenge header"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "Merkle root used in the challenge header"},
                            {RPCResult::Type::NUM, "time", "Current header timestamp used for sigma derivation"},
                            {RPCResult::Type::STR_HEX, "bits", "Compact target encoded in the challenge header"},
                            {RPCResult::Type::NUM, "nonce64_start", "Starting 64-bit nonce for external miners"},
                            {RPCResult::Type::NUM, "matmul_dim", "Matrix dimension encoded in the challenge header"},
                            {RPCResult::Type::STR_HEX, "seed_a", "Matrix seed A encoded in the challenge header"},
                            {RPCResult::Type::STR_HEX, "seed_b", "Matrix seed B encoded in the challenge header"},
                        }},
                        {RPCResult::Type::OBJ, "matmul", "",
                        {
                            {RPCResult::Type::NUM, "n", "Matrix dimension"},
                            {RPCResult::Type::NUM, "b", "Transcript block size"},
                            {RPCResult::Type::NUM, "r", "Noise rank"},
                            {RPCResult::Type::NUM, "q", "Field modulus"},
                            {RPCResult::Type::NUM, "min_dimension", "Minimum dimension"},
                            {RPCResult::Type::NUM, "max_dimension", "Maximum dimension"},
                            {RPCResult::Type::STR_HEX, "seed_a", "Matrix seed A"},
                            {RPCResult::Type::STR_HEX, "seed_b", "Matrix seed B"},
                        }},
                        {RPCResult::Type::OBJ, "work_profile", "Deterministic work profile implied by the active MatMul parameters", {
                            {RPCResult::Type::NUM, "field_element_bytes", "Bytes per field element"},
                            {RPCResult::Type::NUM, "matrix_elements", "Elements in one n x n matrix"},
                            {RPCResult::Type::NUM, "matrix_bytes", "Bytes in one n x n matrix"},
                            {RPCResult::Type::NUM, "matrix_generation_elements_per_seed", "Field elements derived when expanding one matrix seed"},
                            {RPCResult::Type::NUM, "transcript_blocks_per_axis", "Number of transcript blocks along one matrix axis"},
                            {RPCResult::Type::NUM, "transcript_block_multiplications", "b x b block multiplications performed by the canonical transcript"},
                            {RPCResult::Type::NUM, "transcript_field_muladds", "Field multiply-adds from the canonical transcript multiply"},
                            {RPCResult::Type::NUM, "compression_vector_elements", "Elements in one transcript compression vector"},
                            {RPCResult::Type::NUM, "compression_field_muladds", "Field multiply-adds used by transcript block compression"},
                            {RPCResult::Type::NUM, "noise_elements", "Per-nonce field elements derived for low-rank noise matrices"},
                            {RPCResult::Type::NUM, "noise_low_rank_muladds", "Field multiply-adds used to materialize low-rank noise products"},
                            {RPCResult::Type::NUM, "denoise_field_muladds", "Field multiply-adds needed by denoising during validation"},
                            {RPCResult::Type::NUM, "per_nonce_total_field_muladds_estimate", "Transcript plus compression plus low-rank-noise field multiply-add estimate per nonce"},
                            {RPCResult::Type::NUM, "oracle_rejection_probability_per_element", "Probability that one oracle draw needs a retry because it equals the field modulus"},
                            {RPCResult::Type::NUM, "expected_oracle_retries_per_matrix_seed", "Expected retries while expanding one matrix seed"},
                            {RPCResult::Type::NUM, "expected_oracle_retries_per_nonce_noise", "Expected retries while deriving per-nonce noise elements"},
                            {RPCResult::Type::NUM, "pre_hash_epsilon_bits", "Consensus pre-hash epsilon bits used by the sigma lottery gate"},
                            {RPCResult::Type::OBJ, "cross_nonce_reuse", "Upper-bound view of how much fixed per-template work could be amortized across nonce attempts when matrix seeds stay constant within a block template", {
                                {RPCResult::Type::STR, "seed_scope", "Whether matrix seeds are fixed per block template or per nonce"},
                                {RPCResult::Type::STR, "sigma_scope", "Which part of the challenge currently changes across nonce attempts"},
                                {RPCResult::Type::BOOL, "fixed_instance_reuse_possible", "Whether the active challenge shape allows fixed-instance work reuse across nonce attempts"},
                                {RPCResult::Type::NUM, "fixed_matrix_generation_elements_upper_bound", "Upper bound on fixed matrix elements that can be expanded once per template across both seeds"},
                                {RPCResult::Type::NUM, "fixed_clean_product_field_muladds_upper_bound", "Upper bound on clean A*B field multiply-adds that remain fixed across nonce attempts"},
                                {RPCResult::Type::NUM, "dynamic_per_nonce_field_muladds_lower_bound", "Lower bound on field multiply-adds that must still change per nonce even with ideal reuse of fixed template work"},
                                {RPCResult::Type::NUM, "dynamic_per_nonce_share_lower_bound", "Lower-bound share of the advertised per-nonce field multiply-add budget that is necessarily dynamic across nonce attempts"},
                                {RPCResult::Type::NUM, "reusable_work_share_upper_bound", "Upper-bound share of the advertised per-nonce field multiply-add budget that could be amortized across nonce attempts"},
                                {RPCResult::Type::NUM, "amortization_advantage_upper_bound", "Upper bound on per-template speedup if a miner perfectly amortizes all fixed clean-product work across nonce attempts"},
                            }},
                            {RPCResult::Type::OBJ, "next_block_seed_access", "Seed-access semantics for the next block template and whether the current block winner learns the next matrix seeds before the rest of the network", {
                                {RPCResult::Type::STR, "seed_derivation_scope", "Which chain context determines the next block's matrix seeds"},
                                {RPCResult::Type::STR, "seed_derivation_rule", "Consensus rule used to derive seed_a and seed_b"},
                                {RPCResult::Type::BOOL, "winner_knows_next_seeds_first", "Whether the current block winner can derive the next block's seeds before peers receive the parent block"},
                                {RPCResult::Type::BOOL, "publicly_precomputable_before_parent_seen", "Whether non-winning miners can derive the next block's seeds before the parent block hash is visible"},
                                {RPCResult::Type::NUM, "public_precompute_horizon_blocks", "How many blocks ahead the seed inputs are publicly known before the parent is seen"},
                                {RPCResult::Type::NUM, "fixed_matrix_generation_elements_upper_bound", "Upper bound on matrix-expansion field elements gated by the next block's seeds"},
                                {RPCResult::Type::ARR, "template_mutations_preserve_seed", "Template fields that may change while preserving the same seeds", {
                                    {RPCResult::Type::STR, "", "Template field name"},
                                }},
                            }},
                            {RPCResult::Type::OBJ, "pre_hash_lottery", "Consensus-enforced sigma pre-filter semantics relative to the final digest target", {
                                {RPCResult::Type::BOOL, "consensus_enforced", "Whether the sigma lottery is part of the consensus acceptance rule"},
                                {RPCResult::Type::STR, "sigma_rule", "Consensus rule applied to sigma before the expensive MatMul path runs"},
                                {RPCResult::Type::STR, "digest_rule", "Consensus rule applied to the final transcript digest"},
                                {RPCResult::Type::NUM, "epsilon_bits", "Configured pre-hash epsilon bits"},
                                {RPCResult::Type::NUM, "sigma_target_multiplier_vs_digest_target", "How much easier the sigma target is than the final digest target before saturation"},
                                {RPCResult::Type::NUM, "digest_target_probability_per_nonce_estimate", "Estimated probability that one nonce meets the final digest target"},
                                {RPCResult::Type::NUM, "sigma_pass_probability_per_nonce_estimate", "Estimated probability that one nonce passes the consensus sigma gate and reaches MatMul"},
                                {RPCResult::Type::NUM, "expected_sigma_passes_per_digest_hit_estimate", "Estimated sigma passes per final digest hit from the active target ratio"},
                                {RPCResult::Type::NUM, "expected_matmul_invocations_per_1m_nonces_estimate", "Estimated full MatMul invocations per one million scanned nonces"},
                                {RPCResult::Type::BOOL, "target_multiplier_saturated", "Whether left-shifting the active target saturated at the 256-bit limit"},
                            }},
                        }},
                        {RPCResult::Type::OBJ, "service_profile", "", {
                            {RPCResult::Type::NUM, "network_target_s", "Current network target spacing in seconds"},
                            {RPCResult::Type::NUM, "solve_time_target_s", "Solve-time target in seconds"},
                            {RPCResult::Type::NUM, "validation_overhead_s", "Estimated validation overhead in seconds"},
                            {RPCResult::Type::NUM, "propagation_overhead_s", "Estimated propagation overhead in seconds"},
                            {RPCResult::Type::NUM, "overhead_target_s", "Sum of validation and propagation overhead targets"},
                            {RPCResult::Type::NUM, "total_target_s", "Sum of solve and overhead targets"},
                            {RPCResult::Type::NUM, "solve_share_pct", "Percentage of the total target budget allocated to solve time"},
                            {RPCResult::Type::NUM, "validation_share_pct", "Percentage of the total target budget allocated to validation overhead"},
                            {RPCResult::Type::NUM, "propagation_share_pct", "Percentage of the total target budget allocated to propagation overhead"},
                            {RPCResult::Type::NUM, "delta_from_network_s", "Requested solve target minus current network target spacing"},
                            {RPCResult::Type::OBJ, "operator_capacity", "Average-node capacity estimate scaled by the default solver budget", {
                                {RPCResult::Type::STR, "estimation_basis", "Reference model used by the estimate"},
                                {RPCResult::Type::NUM, "solver_parallelism", "Requested independent solver workers"},
                                {RPCResult::Type::NUM, "solver_duty_cycle_pct", "Requested solver duty cycle percentage"},
                                {RPCResult::Type::NUM, "effective_parallelism", "solver_parallelism scaled by solver_duty_cycle_pct"},
                                {RPCResult::Type::NUM, "budgeted_solver_seconds_per_hour", "Budgeted solver-seconds per wall-clock hour"},
                                {RPCResult::Type::NUM, "estimated_sustained_solves_per_hour", "Estimated sustained solves per hour under the requested budget"},
                                {RPCResult::Type::NUM, "estimated_sustained_solves_per_day", "Estimated sustained solves per day under the requested budget"},
                                {RPCResult::Type::NUM, "estimated_mean_seconds_between_solves", "Estimated mean wall-clock seconds between completed solves"},
                            }},
                            {RPCResult::Type::OBJ, "runtime_observability", "Node-local runtime counters observed since process start", {
                                {RPCResult::Type::OBJ, "solve_pipeline", "", {
                                    {RPCResult::Type::BOOL, "async_prepare_enabled", "Whether async nonce preparation is enabled"},
                                    {RPCResult::Type::BOOL, "cpu_confirm_candidates", "Whether candidate digests are CPU-confirmed"},
                                    {RPCResult::Type::NUM, "prepared_inputs", "Prepared input batches observed"},
                                    {RPCResult::Type::NUM, "overlapped_prepares", "Overlapped nonce preparations observed"},
                                    {RPCResult::Type::NUM, "async_prepare_submissions", "Async nonce-prepare submissions observed"},
                                    {RPCResult::Type::NUM, "async_prepare_completions", "Async nonce-prepare completions observed"},
                                    {RPCResult::Type::NUM, "async_prepare_worker_threads", "Prepare worker threads currently configured"},
                                    {RPCResult::Type::NUM, "batch_size", "Configured nonce batch size"},
                                    {RPCResult::Type::NUM, "batched_digest_requests", "Batched digest requests observed"},
                                    {RPCResult::Type::NUM, "batched_nonce_attempts", "Nonce attempts processed via batch execution"},
                                }},
                                {RPCResult::Type::OBJ, "solve_runtime", "", {
                                    {RPCResult::Type::NUM, "attempts", "Solve attempts recorded since process start"},
                                    {RPCResult::Type::NUM, "solved_attempts", "Successful solve attempts recorded since process start"},
                                    {RPCResult::Type::NUM, "failed_attempts", "Failed solve attempts recorded since process start"},
                                    {RPCResult::Type::NUM, "total_elapsed_ms", "Total solve runtime accumulated since process start"},
                                    {RPCResult::Type::NUM, "mean_elapsed_ms", "Mean solve runtime per attempt"},
                                    {RPCResult::Type::NUM, "last_elapsed_ms", "Elapsed time of the latest solve attempt"},
                                    {RPCResult::Type::NUM, "max_elapsed_ms", "Slowest solve attempt observed"},
                                }},
                                {RPCResult::Type::OBJ, "validation_runtime", "", {
                                    {RPCResult::Type::NUM, "phase2_checks", "Total Phase2/Freivalds validation checks recorded since process start"},
                                    {RPCResult::Type::NUM, "freivalds_checks", "Freivalds validation checks recorded since process start"},
                                    {RPCResult::Type::NUM, "transcript_checks", "Full transcript validation checks recorded since process start"},
                                    {RPCResult::Type::NUM, "successful_checks", "Successful Phase2/Freivalds validation checks"},
                                    {RPCResult::Type::NUM, "failed_checks", "Failed Phase2/Freivalds validation checks"},
                                    {RPCResult::Type::NUM, "total_phase2_elapsed_ms", "Total elapsed time for all Phase2/Freivalds checks"},
                                    {RPCResult::Type::NUM, "mean_phase2_elapsed_ms", "Mean elapsed time across all Phase2/Freivalds checks"},
                                    {RPCResult::Type::NUM, "last_phase2_elapsed_ms", "Elapsed time of the latest Phase2/Freivalds check"},
                                    {RPCResult::Type::NUM, "max_phase2_elapsed_ms", "Slowest Phase2/Freivalds check observed"},
                                    {RPCResult::Type::NUM, "total_freivalds_elapsed_ms", "Total elapsed time for Freivalds checks"},
                                    {RPCResult::Type::NUM, "mean_freivalds_elapsed_ms", "Mean elapsed time for Freivalds checks"},
                                    {RPCResult::Type::NUM, "last_freivalds_elapsed_ms", "Elapsed time of the latest Freivalds check"},
                                    {RPCResult::Type::NUM, "max_freivalds_elapsed_ms", "Slowest Freivalds check observed"},
                                    {RPCResult::Type::NUM, "total_transcript_elapsed_ms", "Total elapsed time for full transcript checks"},
                                    {RPCResult::Type::NUM, "mean_transcript_elapsed_ms", "Mean elapsed time for full transcript checks"},
                                    {RPCResult::Type::NUM, "last_transcript_elapsed_ms", "Elapsed time of the latest full transcript check"},
                                    {RPCResult::Type::NUM, "max_transcript_elapsed_ms", "Slowest full transcript check observed"},
                                }},
                                {RPCResult::Type::OBJ, "propagation_proxy", "", {
                                    {RPCResult::Type::BOOL, "network_active", "Whether P2P networking is active"},
                                    {RPCResult::Type::NUM, "connected_peers", "Total connected peers"},
                                    {RPCResult::Type::NUM, "outbound_peers", "Connected outbound peers"},
                                    {RPCResult::Type::NUM, "synced_outbound_peers", "Outbound peers within the configured sync-height lag"},
                                    {RPCResult::Type::NUM, "manual_outbound_peers", "Outbound peers opened with manual connection policy"},
                                    {RPCResult::Type::NUM, "outbound_peers_missing_sync_height", "Outbound peers lacking a reported sync height from net_processing state"},
                                    {RPCResult::Type::NUM, "outbound_peers_beyond_sync_lag", "Outbound peers whose reported sync height exceeds the configured lag threshold"},
                                    {RPCResult::Type::NUM, "recent_block_announcing_outbound_peers", "Outbound peers that have announced at least one block since this process started"},
                                    {RPCResult::Type::NUM, "validated_tip_height", "Current validated tip height"},
                                    {RPCResult::Type::NUM, "best_header_height", "Best known header height"},
                                    {RPCResult::Type::NUM, "header_lag", "Best header height minus validated tip height"},
                                    {RPCResult::Type::NUM, "required_outbound_peers", "Configured outbound peer guard for mining readiness"},
                                    {RPCResult::Type::NUM, "required_synced_outbound_peers", "Configured synced outbound peer guard for mining readiness"},
                                    {RPCResult::Type::NUM, "max_peer_sync_height_lag", "Configured peer sync-height lag guard"},
                                    {RPCResult::Type::NUM, "max_header_lag", "Configured validated-tip header lag guard"},
                                    {RPCResult::Type::ARR, "outbound_peer_diagnostics", "Per-peer outbound readiness diagnostics", {
                                        {RPCResult::Type::OBJ, "", "", {
                                            {RPCResult::Type::STR, "addr", "Peer address or label"},
                                            {RPCResult::Type::STR, "connection_type", "Peer connection type"},
                                            {RPCResult::Type::BOOL, "manual", "Whether the peer is a manual connection"},
                                            {RPCResult::Type::NUM, "sync_height", "Best known validated block height reported for the peer, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "common_height", "Best last-common-block height reported for the peer, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "presync_height", "Presync header height reported for the peer, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "starting_height", "Peer starting height from version handshake"},
                                            {RPCResult::Type::NUM, "sync_lag", "Local validated tip height minus peer sync height, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "last_block_time", "Unix timestamp of the last block relay observed on the connection"},
                                            {RPCResult::Type::NUM, "last_block_announcement", "Unix timestamp of the last block announcement attributed to the peer"},
                                            {RPCResult::Type::BOOL, "counts_as_synced_outbound", "Whether this peer satisfies the synced-outbound readiness rule"},
                                        }},
                                    }},
                                }},
                                {RPCResult::Type::OBJ, "reorg_protection", "", {
                                    {RPCResult::Type::BOOL, "enabled", "Whether explicit deep-reorg protection is configured"},
                                    {RPCResult::Type::BOOL, "active", "Whether the chain tip is at or above the protection activation height"},
                                    {RPCResult::Type::NUM, "current_tip_height", "Current active tip height used for activation checks"},
                                    {RPCResult::Type::NUM, "start_height", "Configured activation height for deep-reorg protection"},
                                    {RPCResult::Type::NUM, "max_reorg_depth", "Configured maximum permitted reorganization depth"},
                                    {RPCResult::Type::NUM, "rejected_reorgs", "Rejected deep reorgs recorded since process start"},
                                    {RPCResult::Type::NUM, "deepest_rejected_reorg_depth", "Deepest rejected reorg observed since process start"},
                                    {RPCResult::Type::NUM, "last_rejected_reorg_depth", "Depth of the most recent rejected reorg"},
                                    {RPCResult::Type::NUM, "last_rejected_max_reorg_depth", "Configured max depth in effect for the most recent rejection"},
                                    {RPCResult::Type::NUM, "last_rejected_tip_height", "Active tip height when the most recent rejection occurred"},
                                    {RPCResult::Type::NUM, "last_rejected_fork_height", "Fork point height for the most recent rejection"},
                                    {RPCResult::Type::NUM, "last_rejected_candidate_height", "Candidate chain height for the most recent rejection"},
                                    {RPCResult::Type::NUM, "last_rejected_unix", "Unix timestamp of the most recent rejected reorg"},
                                }},
                                {RPCResult::Type::OBJ, "backend_runtime", "", {
                                    {RPCResult::Type::NUM, "digest_requests", "Digest requests served"},
                                    {RPCResult::Type::NUM, "requested_cpu", "Digest requests targeting CPU"},
                                    {RPCResult::Type::NUM, "requested_metal", "Digest requests targeting Metal"},
                                    {RPCResult::Type::NUM, "requested_cuda", "Digest requests targeting CUDA"},
                                    {RPCResult::Type::NUM, "requested_unknown", "Digest requests targeting an unknown backend"},
                                    {RPCResult::Type::NUM, "metal_successes", "Successful Metal digest computations"},
                                    {RPCResult::Type::NUM, "metal_fallbacks_to_cpu", "Metal requests that fell back to CPU"},
                                    {RPCResult::Type::NUM, "metal_digest_mismatches", "Metal digest mismatches detected"},
                                    {RPCResult::Type::NUM, "metal_retry_without_uploaded_base_attempts", "Metal retries attempted without uploaded base matrices"},
                                    {RPCResult::Type::NUM, "metal_retry_without_uploaded_base_successes", "Successful retries without uploaded base matrices"},
                                    {RPCResult::Type::NUM, "gpu_input_generation_attempts", "GPU input-generation attempts"},
                                    {RPCResult::Type::NUM, "gpu_input_generation_successes", "Successful GPU input-generation attempts"},
                                    {RPCResult::Type::NUM, "gpu_input_generation_failures", "Failed GPU input-generation attempts"},
                                    {RPCResult::Type::NUM, "gpu_input_auto_disabled_skips", "AUTO-mode GPU input skips after disablement"},
                                    {RPCResult::Type::BOOL, "gpu_input_auto_disabled", "Whether GPU input AUTO mode is disabled"},
                                    {RPCResult::Type::STR, "last_metal_fallback_error", "Most recent Metal fallback error"},
                                    {RPCResult::Type::STR, "last_gpu_input_error", "Most recent GPU input-generation error"},
                                }},
                            }},
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("getmatmulchallenge", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulChallengeResponse(
        chainman,
        node,
        static_cast<double>(chainman.GetConsensus().nPowTargetSpacing),
        0.0,
        0.0);
},
    };
}

static RPCHelpMan getmatmulchallengeprofile()
{
    return RPCHelpMan{"getmatmulchallengeprofile",
                "\nReturns a MatMul challenge profile for the active chain at the requested solve-time target.\n",
                {
                    {"target_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{90}, "Requested solve-time target in seconds"},
                    {"validation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated validation overhead in seconds"},
                    {"propagation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated propagation overhead in seconds"},
                    {"solver_parallelism", RPCArg::Type::NUM, RPCArg::Default{1}, "Expected number of independent solver workers available to the miner or agent"},
                    {"solver_duty_cycle_pct", RPCArg::Type::NUM, RPCArg::Default{100}, "Expected share of wall-clock time those solver workers may use, for example 35 for idle-time mining"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "chain", "Current network name"},
                        {RPCResult::Type::STR, "algorithm", "Proof-of-work algorithm"},
                        {RPCResult::Type::NUM, "height", "Next height"},
                        {RPCResult::Type::STR_HEX, "previousblockhash", "Current tip hash"},
                        {RPCResult::Type::NUM, "mintime", "Minimum block time for the next block"},
                        {RPCResult::Type::STR_HEX, "bits", "Compact target"},
                        {RPCResult::Type::NUM, "difficulty", "Difficulty"},
                        {RPCResult::Type::STR_HEX, "target", "Target"},
                        {RPCResult::Type::STR, "noncerange", "Nonce search range"},
                        {RPCResult::Type::OBJ, "header_context", "Exact block-header fields used for sigma derivation before nonce scanning", {
                            {RPCResult::Type::NUM, "version", "Block version used in the challenge header"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", "Previous block hash used in the challenge header"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "Merkle root used in the challenge header"},
                            {RPCResult::Type::NUM, "time", "Current header timestamp used for sigma derivation"},
                            {RPCResult::Type::STR_HEX, "bits", "Compact target encoded in the challenge header"},
                            {RPCResult::Type::NUM, "nonce64_start", "Starting 64-bit nonce for external miners"},
                            {RPCResult::Type::NUM, "matmul_dim", "Matrix dimension encoded in the challenge header"},
                            {RPCResult::Type::STR_HEX, "seed_a", "Matrix seed A encoded in the challenge header"},
                            {RPCResult::Type::STR_HEX, "seed_b", "Matrix seed B encoded in the challenge header"},
                        }},
                        {RPCResult::Type::OBJ, "matmul", "",
                        {
                            {RPCResult::Type::NUM, "n", "Matrix dimension"},
                            {RPCResult::Type::NUM, "b", "Transcript block size"},
                            {RPCResult::Type::NUM, "r", "Noise rank"},
                            {RPCResult::Type::NUM, "q", "Field modulus"},
                            {RPCResult::Type::NUM, "min_dimension", "Minimum dimension"},
                            {RPCResult::Type::NUM, "max_dimension", "Maximum dimension"},
                            {RPCResult::Type::STR_HEX, "seed_a", "Matrix seed A"},
                            {RPCResult::Type::STR_HEX, "seed_b", "Matrix seed B"},
                        }},
                        {RPCResult::Type::OBJ, "work_profile", "Deterministic work profile implied by the active MatMul parameters", {
                            {RPCResult::Type::NUM, "field_element_bytes", "Bytes per field element"},
                            {RPCResult::Type::NUM, "matrix_elements", "Elements in one n x n matrix"},
                            {RPCResult::Type::NUM, "matrix_bytes", "Bytes in one n x n matrix"},
                            {RPCResult::Type::NUM, "matrix_generation_elements_per_seed", "Field elements derived when expanding one matrix seed"},
                            {RPCResult::Type::NUM, "transcript_blocks_per_axis", "Number of transcript blocks along one matrix axis"},
                            {RPCResult::Type::NUM, "transcript_block_multiplications", "b x b block multiplications performed by the canonical transcript"},
                            {RPCResult::Type::NUM, "transcript_field_muladds", "Field multiply-adds from the canonical transcript multiply"},
                            {RPCResult::Type::NUM, "compression_vector_elements", "Elements in one transcript compression vector"},
                            {RPCResult::Type::NUM, "compression_field_muladds", "Field multiply-adds used by transcript block compression"},
                            {RPCResult::Type::NUM, "noise_elements", "Per-nonce field elements derived for low-rank noise matrices"},
                            {RPCResult::Type::NUM, "noise_low_rank_muladds", "Field multiply-adds used to materialize low-rank noise products"},
                            {RPCResult::Type::NUM, "denoise_field_muladds", "Field multiply-adds needed by denoising during validation"},
                            {RPCResult::Type::NUM, "per_nonce_total_field_muladds_estimate", "Transcript plus compression plus low-rank-noise field multiply-add estimate per nonce"},
                            {RPCResult::Type::NUM, "oracle_rejection_probability_per_element", "Probability that one oracle draw needs a retry because it equals the field modulus"},
                            {RPCResult::Type::NUM, "expected_oracle_retries_per_matrix_seed", "Expected retries while expanding one matrix seed"},
                            {RPCResult::Type::NUM, "expected_oracle_retries_per_nonce_noise", "Expected retries while deriving per-nonce noise elements"},
                            {RPCResult::Type::NUM, "pre_hash_epsilon_bits", "Consensus pre-hash epsilon bits used by the sigma lottery gate"},
                            {RPCResult::Type::OBJ, "cross_nonce_reuse", "Upper-bound view of how much fixed per-template work could be amortized across nonce attempts when matrix seeds stay constant within a block template", {
                                {RPCResult::Type::STR, "seed_scope", "Whether matrix seeds are fixed per block template or per nonce"},
                                {RPCResult::Type::STR, "sigma_scope", "Which part of the challenge currently changes across nonce attempts"},
                                {RPCResult::Type::BOOL, "fixed_instance_reuse_possible", "Whether the active challenge shape allows fixed-instance work reuse across nonce attempts"},
                                {RPCResult::Type::NUM, "fixed_matrix_generation_elements_upper_bound", "Upper bound on fixed matrix elements that can be expanded once per template across both seeds"},
                                {RPCResult::Type::NUM, "fixed_clean_product_field_muladds_upper_bound", "Upper bound on clean A*B field multiply-adds that remain fixed across nonce attempts"},
                                {RPCResult::Type::NUM, "dynamic_per_nonce_field_muladds_lower_bound", "Lower bound on field multiply-adds that must still change per nonce even with ideal reuse of fixed template work"},
                                {RPCResult::Type::NUM, "dynamic_per_nonce_share_lower_bound", "Lower-bound share of the advertised per-nonce field multiply-add budget that is necessarily dynamic across nonce attempts"},
                                {RPCResult::Type::NUM, "reusable_work_share_upper_bound", "Upper-bound share of the advertised per-nonce field multiply-add budget that could be amortized across nonce attempts"},
                                {RPCResult::Type::NUM, "amortization_advantage_upper_bound", "Upper bound on per-template speedup if a miner perfectly amortizes all fixed clean-product work across nonce attempts"},
                            }},
                            {RPCResult::Type::OBJ, "next_block_seed_access", "Seed-access semantics for the next block template and whether the current block winner learns the next matrix seeds before the rest of the network", {
                                {RPCResult::Type::STR, "seed_derivation_scope", "Which chain context determines the next block's matrix seeds"},
                                {RPCResult::Type::STR, "seed_derivation_rule", "Consensus rule used to derive seed_a and seed_b"},
                                {RPCResult::Type::BOOL, "winner_knows_next_seeds_first", "Whether the current block winner can derive the next block's seeds before peers receive the parent block"},
                                {RPCResult::Type::BOOL, "publicly_precomputable_before_parent_seen", "Whether non-winning miners can derive the next block's seeds before the parent block hash is visible"},
                                {RPCResult::Type::NUM, "public_precompute_horizon_blocks", "How many blocks ahead the seed inputs are publicly known before the parent is seen"},
                                {RPCResult::Type::NUM, "fixed_matrix_generation_elements_upper_bound", "Upper bound on matrix-expansion field elements gated by the next block's seeds"},
                                {RPCResult::Type::ARR, "template_mutations_preserve_seed", "Template fields that may change while preserving the same seeds", {
                                    {RPCResult::Type::STR, "", "Template field name"},
                                }},
                            }},
                            {RPCResult::Type::OBJ, "pre_hash_lottery", "Consensus-enforced sigma pre-filter semantics relative to the final digest target", {
                                {RPCResult::Type::BOOL, "consensus_enforced", "Whether the sigma lottery is part of the consensus acceptance rule"},
                                {RPCResult::Type::STR, "sigma_rule", "Consensus rule applied to sigma before the expensive MatMul path runs"},
                                {RPCResult::Type::STR, "digest_rule", "Consensus rule applied to the final transcript digest"},
                                {RPCResult::Type::NUM, "epsilon_bits", "Configured pre-hash epsilon bits"},
                                {RPCResult::Type::NUM, "sigma_target_multiplier_vs_digest_target", "How much easier the sigma target is than the final digest target before saturation"},
                                {RPCResult::Type::NUM, "digest_target_probability_per_nonce_estimate", "Estimated probability that one nonce meets the final digest target"},
                                {RPCResult::Type::NUM, "sigma_pass_probability_per_nonce_estimate", "Estimated probability that one nonce passes the consensus sigma gate and reaches MatMul"},
                                {RPCResult::Type::NUM, "expected_sigma_passes_per_digest_hit_estimate", "Estimated sigma passes per final digest hit from the active target ratio"},
                                {RPCResult::Type::NUM, "expected_matmul_invocations_per_1m_nonces_estimate", "Estimated full MatMul invocations per one million scanned nonces"},
                                {RPCResult::Type::BOOL, "target_multiplier_saturated", "Whether left-shifting the active target saturated at the 256-bit limit"},
                            }},
                        }},
                        {RPCResult::Type::OBJ, "service_profile", "", {
                            {RPCResult::Type::NUM, "network_target_s", "Current network target spacing in seconds"},
                            {RPCResult::Type::NUM, "solve_time_target_s", "Solve-time target in seconds"},
                            {RPCResult::Type::NUM, "validation_overhead_s", "Estimated validation overhead in seconds"},
                            {RPCResult::Type::NUM, "propagation_overhead_s", "Estimated propagation overhead in seconds"},
                            {RPCResult::Type::NUM, "overhead_target_s", "Sum of validation and propagation overhead targets"},
                            {RPCResult::Type::NUM, "total_target_s", "Sum of solve and overhead targets"},
                            {RPCResult::Type::NUM, "solve_share_pct", "Percentage of the total target budget allocated to solve time"},
                            {RPCResult::Type::NUM, "validation_share_pct", "Percentage of the total target budget allocated to validation overhead"},
                            {RPCResult::Type::NUM, "propagation_share_pct", "Percentage of the total target budget allocated to propagation overhead"},
                            {RPCResult::Type::NUM, "delta_from_network_s", "Requested solve target minus current network target spacing"},
                            {RPCResult::Type::OBJ, "operator_capacity", "Average-node capacity estimate scaled by the requested solver budget", {
                                {RPCResult::Type::STR, "estimation_basis", "Reference model used by the estimate"},
                                {RPCResult::Type::NUM, "solver_parallelism", "Requested independent solver workers"},
                                {RPCResult::Type::NUM, "solver_duty_cycle_pct", "Requested solver duty cycle percentage"},
                                {RPCResult::Type::NUM, "effective_parallelism", "solver_parallelism scaled by solver_duty_cycle_pct"},
                                {RPCResult::Type::NUM, "budgeted_solver_seconds_per_hour", "Budgeted solver-seconds per wall-clock hour"},
                                {RPCResult::Type::NUM, "estimated_sustained_solves_per_hour", "Estimated sustained solves per hour under the requested budget"},
                                {RPCResult::Type::NUM, "estimated_sustained_solves_per_day", "Estimated sustained solves per day under the requested budget"},
                                {RPCResult::Type::NUM, "estimated_mean_seconds_between_solves", "Estimated mean wall-clock seconds between completed solves"},
                            }},
                            {RPCResult::Type::OBJ, "runtime_observability", "Node-local runtime counters observed since process start", {
                                {RPCResult::Type::OBJ, "solve_pipeline", "", {
                                    {RPCResult::Type::BOOL, "async_prepare_enabled", "Whether async nonce preparation is enabled"},
                                    {RPCResult::Type::BOOL, "cpu_confirm_candidates", "Whether candidate digests are CPU-confirmed"},
                                    {RPCResult::Type::NUM, "prepared_inputs", "Prepared input batches observed"},
                                    {RPCResult::Type::NUM, "overlapped_prepares", "Overlapped nonce preparations observed"},
                                    {RPCResult::Type::NUM, "async_prepare_submissions", "Async nonce-prepare submissions observed"},
                                    {RPCResult::Type::NUM, "async_prepare_completions", "Async nonce-prepare completions observed"},
                                    {RPCResult::Type::NUM, "async_prepare_worker_threads", "Prepare worker threads currently configured"},
                                    {RPCResult::Type::NUM, "batch_size", "Configured nonce batch size"},
                                    {RPCResult::Type::NUM, "batched_digest_requests", "Batched digest requests observed"},
                                    {RPCResult::Type::NUM, "batched_nonce_attempts", "Nonce attempts processed via batch execution"},
                                }},
                                {RPCResult::Type::OBJ, "solve_runtime", "", {
                                    {RPCResult::Type::NUM, "attempts", "Solve attempts recorded since process start"},
                                    {RPCResult::Type::NUM, "solved_attempts", "Successful solve attempts recorded since process start"},
                                    {RPCResult::Type::NUM, "failed_attempts", "Failed solve attempts recorded since process start"},
                                    {RPCResult::Type::NUM, "total_elapsed_ms", "Total solve runtime accumulated since process start"},
                                    {RPCResult::Type::NUM, "mean_elapsed_ms", "Mean solve runtime per attempt"},
                                    {RPCResult::Type::NUM, "last_elapsed_ms", "Elapsed time of the latest solve attempt"},
                                    {RPCResult::Type::NUM, "max_elapsed_ms", "Slowest solve attempt observed"},
                                }},
                                {RPCResult::Type::OBJ, "validation_runtime", "", {
                                    {RPCResult::Type::NUM, "phase2_checks", "Total Phase2/Freivalds validation checks recorded since process start"},
                                    {RPCResult::Type::NUM, "freivalds_checks", "Freivalds validation checks recorded since process start"},
                                    {RPCResult::Type::NUM, "transcript_checks", "Full transcript validation checks recorded since process start"},
                                    {RPCResult::Type::NUM, "successful_checks", "Successful Phase2/Freivalds validation checks"},
                                    {RPCResult::Type::NUM, "failed_checks", "Failed Phase2/Freivalds validation checks"},
                                    {RPCResult::Type::NUM, "total_phase2_elapsed_ms", "Total elapsed time for all Phase2/Freivalds checks"},
                                    {RPCResult::Type::NUM, "mean_phase2_elapsed_ms", "Mean elapsed time across all Phase2/Freivalds checks"},
                                    {RPCResult::Type::NUM, "last_phase2_elapsed_ms", "Elapsed time of the latest Phase2/Freivalds check"},
                                    {RPCResult::Type::NUM, "max_phase2_elapsed_ms", "Slowest Phase2/Freivalds check observed"},
                                    {RPCResult::Type::NUM, "total_freivalds_elapsed_ms", "Total elapsed time for Freivalds checks"},
                                    {RPCResult::Type::NUM, "mean_freivalds_elapsed_ms", "Mean elapsed time for Freivalds checks"},
                                    {RPCResult::Type::NUM, "last_freivalds_elapsed_ms", "Elapsed time of the latest Freivalds check"},
                                    {RPCResult::Type::NUM, "max_freivalds_elapsed_ms", "Slowest Freivalds check observed"},
                                    {RPCResult::Type::NUM, "total_transcript_elapsed_ms", "Total elapsed time for full transcript checks"},
                                    {RPCResult::Type::NUM, "mean_transcript_elapsed_ms", "Mean elapsed time for full transcript checks"},
                                    {RPCResult::Type::NUM, "last_transcript_elapsed_ms", "Elapsed time of the latest full transcript check"},
                                    {RPCResult::Type::NUM, "max_transcript_elapsed_ms", "Slowest full transcript check observed"},
                                }},
                                {RPCResult::Type::OBJ, "propagation_proxy", "", {
                                    {RPCResult::Type::BOOL, "network_active", "Whether P2P networking is active"},
                                    {RPCResult::Type::NUM, "connected_peers", "Total connected peers"},
                                    {RPCResult::Type::NUM, "outbound_peers", "Connected outbound peers"},
                                    {RPCResult::Type::NUM, "synced_outbound_peers", "Outbound peers within the configured sync-height lag"},
                                    {RPCResult::Type::NUM, "manual_outbound_peers", "Outbound peers opened with manual connection policy"},
                                    {RPCResult::Type::NUM, "outbound_peers_missing_sync_height", "Outbound peers lacking a reported sync height from net_processing state"},
                                    {RPCResult::Type::NUM, "outbound_peers_beyond_sync_lag", "Outbound peers whose reported sync height exceeds the configured lag threshold"},
                                    {RPCResult::Type::NUM, "recent_block_announcing_outbound_peers", "Outbound peers that have announced at least one block since this process started"},
                                    {RPCResult::Type::NUM, "validated_tip_height", "Current validated tip height"},
                                    {RPCResult::Type::NUM, "best_header_height", "Best known header height"},
                                    {RPCResult::Type::NUM, "header_lag", "Best header height minus validated tip height"},
                                    {RPCResult::Type::NUM, "required_outbound_peers", "Configured outbound peer guard for mining readiness"},
                                    {RPCResult::Type::NUM, "required_synced_outbound_peers", "Configured synced outbound peer guard for mining readiness"},
                                    {RPCResult::Type::NUM, "max_peer_sync_height_lag", "Configured peer sync-height lag guard"},
                                    {RPCResult::Type::NUM, "max_header_lag", "Configured validated-tip header lag guard"},
                                    {RPCResult::Type::ARR, "outbound_peer_diagnostics", "Per-peer outbound readiness diagnostics", {
                                        {RPCResult::Type::OBJ, "", "", {
                                            {RPCResult::Type::STR, "addr", "Peer address or label"},
                                            {RPCResult::Type::STR, "connection_type", "Peer connection type"},
                                            {RPCResult::Type::BOOL, "manual", "Whether the peer is a manual connection"},
                                            {RPCResult::Type::NUM, "sync_height", "Best known validated block height reported for the peer, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "common_height", "Best last-common-block height reported for the peer, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "presync_height", "Presync header height reported for the peer, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "starting_height", "Peer starting height from version handshake"},
                                            {RPCResult::Type::NUM, "sync_lag", "Local validated tip height minus peer sync height, or -1 if unavailable"},
                                            {RPCResult::Type::NUM, "last_block_time", "Unix timestamp of the last block relay observed on the connection"},
                                            {RPCResult::Type::NUM, "last_block_announcement", "Unix timestamp of the last block announcement attributed to the peer"},
                                            {RPCResult::Type::BOOL, "counts_as_synced_outbound", "Whether this peer satisfies the synced-outbound readiness rule"},
                                        }},
                                    }},
                                }},
                                {RPCResult::Type::OBJ, "reorg_protection", "", {
                                    {RPCResult::Type::BOOL, "enabled", "Whether explicit deep-reorg protection is configured"},
                                    {RPCResult::Type::BOOL, "active", "Whether the chain tip is at or above the protection activation height"},
                                    {RPCResult::Type::NUM, "current_tip_height", "Current active tip height used for activation checks"},
                                    {RPCResult::Type::NUM, "start_height", "Configured activation height for deep-reorg protection"},
                                    {RPCResult::Type::NUM, "max_reorg_depth", "Configured maximum permitted reorganization depth"},
                                    {RPCResult::Type::NUM, "rejected_reorgs", "Rejected deep reorgs recorded since process start"},
                                    {RPCResult::Type::NUM, "deepest_rejected_reorg_depth", "Deepest rejected reorg observed since process start"},
                                    {RPCResult::Type::NUM, "last_rejected_reorg_depth", "Depth of the most recent rejected reorg"},
                                    {RPCResult::Type::NUM, "last_rejected_max_reorg_depth", "Configured max depth in effect for the most recent rejection"},
                                    {RPCResult::Type::NUM, "last_rejected_tip_height", "Active tip height when the most recent rejection occurred"},
                                    {RPCResult::Type::NUM, "last_rejected_fork_height", "Fork point height for the most recent rejection"},
                                    {RPCResult::Type::NUM, "last_rejected_candidate_height", "Candidate chain height for the most recent rejection"},
                                    {RPCResult::Type::NUM, "last_rejected_unix", "Unix timestamp of the most recent rejected reorg"},
                                }},
                                {RPCResult::Type::OBJ, "backend_runtime", "", {
                                    {RPCResult::Type::NUM, "digest_requests", "Digest requests served"},
                                    {RPCResult::Type::NUM, "requested_cpu", "Digest requests targeting CPU"},
                                    {RPCResult::Type::NUM, "requested_metal", "Digest requests targeting Metal"},
                                    {RPCResult::Type::NUM, "requested_cuda", "Digest requests targeting CUDA"},
                                    {RPCResult::Type::NUM, "requested_unknown", "Digest requests targeting an unknown backend"},
                                    {RPCResult::Type::NUM, "metal_successes", "Successful Metal digest computations"},
                                    {RPCResult::Type::NUM, "metal_fallbacks_to_cpu", "Metal requests that fell back to CPU"},
                                    {RPCResult::Type::NUM, "metal_digest_mismatches", "Metal digest mismatches detected"},
                                    {RPCResult::Type::NUM, "metal_retry_without_uploaded_base_attempts", "Metal retries attempted without uploaded base matrices"},
                                    {RPCResult::Type::NUM, "metal_retry_without_uploaded_base_successes", "Successful retries without uploaded base matrices"},
                                    {RPCResult::Type::NUM, "gpu_input_generation_attempts", "GPU input-generation attempts"},
                                    {RPCResult::Type::NUM, "gpu_input_generation_successes", "Successful GPU input-generation attempts"},
                                    {RPCResult::Type::NUM, "gpu_input_generation_failures", "Failed GPU input-generation attempts"},
                                    {RPCResult::Type::NUM, "gpu_input_auto_disabled_skips", "AUTO-mode GPU input skips after disablement"},
                                    {RPCResult::Type::BOOL, "gpu_input_auto_disabled", "Whether GPU input AUTO mode is disabled"},
                                    {RPCResult::Type::STR, "last_metal_fallback_error", "Most recent Metal fallback error"},
                                    {RPCResult::Type::STR, "last_gpu_input_error", "Most recent GPU input-generation error"},
                                }},
                            }},
                        }},
                    },
                },
                RPCExamples{
                    HelpExampleCli("getmatmulchallengeprofile", "1")
            + HelpExampleCli("getmatmulchallengeprofile", "1 0.25 0.75")
            + HelpExampleCli("getmatmulchallengeprofile", "90 0.25 0.75 2 35")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const double target_solve_time_s = request.params[0].isNull() ? 90.0 : request.params[0].get_real();
    const double validation_overhead_s = request.params[1].isNull() ? 0.0 : request.params[1].get_real();
    const double propagation_overhead_s = request.params[2].isNull() ? 0.0 : request.params[2].get_real();
    const int solver_parallelism =
        request.params[3].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM : request.params[3].getInt<int>();
    const double solver_duty_cycle_pct =
        request.params[4].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT : request.params[4].get_real();
    if (!(target_solve_time_s > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "target_solve_time_s must be positive");
    }
    if (validation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "validation_overhead_s must be non-negative");
    }
    if (propagation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "propagation_overhead_s must be non-negative");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulChallengeResponse(
        chainman,
        node,
        target_solve_time_s,
        validation_overhead_s,
        propagation_overhead_s,
        nullptr,
        solver_parallelism,
        solver_duty_cycle_pct);
},
    };
}

static RPCHelpMan getmatmulservicechallenge()
{
    return RPCHelpMan{"getmatmulservicechallenge",
                "\nReturns a domain-bound MatMul service challenge for application-side rate limiting, spam control, or proof-of-work gating.\n",
                {
                    {"purpose", RPCArg::Type::STR, RPCArg::Optional::NO, "Application policy label, for example rate_limit"},
                    {"resource", RPCArg::Type::STR, RPCArg::Optional::NO, "Bound resource identifier, for example signup:/v1/messages"},
                    {"subject", RPCArg::Type::STR, RPCArg::Optional::NO, "Bound subject identifier, for example user:alice@example.com"},
                    {"target_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{1}, "Requested service solve-time target in seconds"},
                    {"expires_in_s", RPCArg::Type::NUM, RPCArg::Default{300}, "Challenge lifetime in seconds"},
                    {"validation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated validation overhead in seconds"},
                    {"propagation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated propagation overhead in seconds"},
                    {"difficulty_policy", RPCArg::Type::STR, RPCArg::Default{"fixed"}, "Difficulty policy: fixed or adaptive_window"},
                    {"difficulty_window_blocks", RPCArg::Type::NUM, RPCArg::Default{24}, "Recent block window used when difficulty_policy=adaptive_window"},
                    {"min_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{0.25}, "Minimum solve-time target after adaptive_window scaling"},
                    {"max_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{30}, "Maximum solve-time target after adaptive_window scaling"},
                    {"solver_parallelism", RPCArg::Type::NUM, RPCArg::Default{1}, "Expected number of independent solver workers on the client or gateway tier"},
                    {"solver_duty_cycle_pct", RPCArg::Type::NUM, RPCArg::Default{100}, "Expected share of wall-clock time those workers may use"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "kind", "Challenge envelope kind"},
                        {RPCResult::Type::STR_HEX, "challenge_id", "Challenge identifier"},
                        {RPCResult::Type::NUM, "issued_at", "Unix timestamp when the challenge was issued"},
                        {RPCResult::Type::NUM, "expires_at", "Unix timestamp when the challenge expires"},
                        {RPCResult::Type::NUM, "expires_in_s", "Challenge lifetime in seconds"},
                        {RPCResult::Type::ANY, "binding", "Application binding plus anchor metadata"},
                        {RPCResult::Type::ANY, "proof_policy", "Verification policy for the service proof"},
                        {RPCResult::Type::ANY, "challenge", "MatMul challenge payload and service profile"},
                    },
                },
                RPCExamples{
                    HelpExampleCli(
                        "getmatmulservicechallenge",
                        "\"rate_limit\" \"signup:/v1/messages\" \"user:alice@example.com\" 2 300 0.25 0.75")
                    + HelpExampleCli(
                        "getmatmulservicechallenge",
                        "\"rate_limit\" \"signup:/v1/messages\" \"user:alice@example.com\" 2 300 0.25 0.75 \"adaptive_window\" 24 0.25 6")
                    + HelpExampleCli(
                        "getmatmulservicechallenge",
                        "\"rate_limit\" \"signup:/v1/messages\" \"user:alice@example.com\" 2 300 0.25 0.75 \"adaptive_window\" 24 0.25 6 4 25")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string purpose = request.params[0].get_str();
    const std::string resource = request.params[1].get_str();
    const std::string subject = request.params[2].get_str();
    const double target_solve_time_s = request.params[3].isNull() ? 1.0 : request.params[3].get_real();
    const int64_t expires_in_s = request.params[4].isNull() ? 300 : request.params[4].getInt<int64_t>();
    const double validation_overhead_s = request.params[5].isNull() ? 0.0 : request.params[5].get_real();
    const double propagation_overhead_s = request.params[6].isNull() ? 0.0 : request.params[6].get_real();
    const std::string difficulty_policy =
        request.params[7].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED : request.params[7].get_str();
    const int difficulty_window_blocks =
        request.params[8].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_DEFAULT_WINDOW_BLOCKS : request.params[8].getInt<int>();
    const double min_solve_time_s =
        request.params[9].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MIN_SOLVE_TIME_S : request.params[9].get_real();
    const double max_solve_time_s =
        request.params[10].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MAX_SOLVE_TIME_S : request.params[10].get_real();
    const int solver_parallelism =
        request.params[11].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM : request.params[11].getInt<int>();
    const double solver_duty_cycle_pct =
        request.params[12].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT : request.params[12].get_real();
    if (!(target_solve_time_s > 0.0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "target_solve_time_s must be positive");
    }
    if (expires_in_s < 1 || expires_in_s > MATMUL_SERVICE_MAX_EXPIRY_S) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "expires_in_s must be between 1 and 86400");
    }
    if (validation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "validation_overhead_s must be non-negative");
    }
    if (propagation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "propagation_overhead_s must be non-negative");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulServiceChallengeResponse(
        chainman,
        node,
        purpose,
        resource,
        subject,
        target_solve_time_s,
        expires_in_s,
        validation_overhead_s,
        propagation_overhead_s,
        difficulty_policy,
        difficulty_window_blocks,
        min_solve_time_s,
        max_solve_time_s,
        solver_parallelism,
        solver_duty_cycle_pct);
},
    };
}

static RPCHelpMan getmatmulservicechallengeplan()
{
    return RPCHelpMan{MATMUL_SERVICE_CHALLENGE_PLAN_RPC,
                "\nPlans a ready-to-issue MatMul service challenge budget from an operator throughput objective.\n",
                {
                    {"objective_mode", RPCArg::Type::STR, RPCArg::Optional::NO, "Planning objective: solves_per_hour, solves_per_day, or mean_seconds_between_solves"},
                    {"objective_value", RPCArg::Type::NUM, RPCArg::Optional::NO, "Requested value for objective_mode"},
                    {"validation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated validation overhead in seconds"},
                    {"propagation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated propagation overhead in seconds"},
                    {"difficulty_policy", RPCArg::Type::STR, RPCArg::Default{"fixed"}, "Difficulty policy used for the plan: fixed or adaptive_window"},
                    {"difficulty_window_blocks", RPCArg::Type::NUM, RPCArg::Default{24}, "Recent block window used when difficulty_policy=adaptive_window"},
                    {"min_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{0.25}, "Minimum solve-time target allowed after policy resolution"},
                    {"max_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{30}, "Maximum solve-time target allowed after policy resolution"},
                    {"solver_parallelism", RPCArg::Type::NUM, RPCArg::Default{1}, "Expected number of independent solver workers on the client or gateway tier"},
                    {"solver_duty_cycle_pct", RPCArg::Type::NUM, RPCArg::Default{100}, "Expected share of wall-clock time those workers may use"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "objective", "Canonicalized planning objective", {
                            {RPCResult::Type::STR, "mode", "Canonical planning objective name"},
                            {RPCResult::Type::NUM, "requested_value", "Requested value for the selected objective"},
                            {RPCResult::Type::NUM, "requested_sustained_solves_per_hour", "Requested sustained solves per hour implied by the objective"},
                            {RPCResult::Type::NUM, "requested_sustained_solves_per_day", "Requested sustained solves per day implied by the objective"},
                            {RPCResult::Type::NUM, "requested_mean_seconds_between_solves", "Requested mean wall-clock seconds between solves implied by the objective"},
                            {RPCResult::Type::NUM, "requested_total_target_s", "Requested total wall-clock budget per solve under the supplied solver budget"},
                            {RPCResult::Type::NUM, "requested_resolved_solve_time_s", "Requested post-policy solve-time budget after subtracting validation and propagation overheads"},
                        }},
                        {RPCResult::Type::OBJ, "plan", "Direct issuance plan for getmatmulservicechallenge", {
                            {RPCResult::Type::BOOL, "objective_satisfied", "Whether the resolved plan still satisfies the requested throughput objective"},
                            {RPCResult::Type::NUM, "requested_base_solve_time_s", "Base target_solve_time_s to pass to getmatmulservicechallenge"},
                            {RPCResult::Type::NUM, "resolved_target_solve_time_s", "Resolved solve-time target after applying the difficulty policy"},
                            {RPCResult::Type::NUM, "resolved_total_target_s", "Resolved solve time plus validation and propagation overheads"},
                            {RPCResult::Type::NUM, "validation_overhead_s", "Validation overhead used by the plan"},
                            {RPCResult::Type::NUM, "propagation_overhead_s", "Propagation overhead used by the plan"},
                            {RPCResult::Type::ANY, "difficulty_resolution", "Resolved difficulty policy shaped like getmatmulservicechallengeprofile.profile.difficulty_resolution"},
                            {RPCResult::Type::ANY, "operator_capacity", "Resolved operator capacity shaped like getmatmulservicechallengeprofile.profile.operator_capacity"},
                            {RPCResult::Type::ANY, "objective_gap", "Requested versus actual throughput delta for the plan"},
                            {RPCResult::Type::OBJ, "issue_defaults", "Ready-to-pass defaults for getmatmulservicechallenge", {
                                {RPCResult::Type::STR, "rpc", "Challenge-issuance RPC name"},
                                {RPCResult::Type::NUM, "target_solve_time_s", "Base solve-time target to pass to getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "resolved_target_solve_time_s", "Expected resolved solve-time target after applying the difficulty policy"},
                                {RPCResult::Type::NUM, "validation_overhead_s", "Validation overhead field for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "propagation_overhead_s", "Propagation overhead field for getmatmulservicechallenge"},
                                {RPCResult::Type::STR, "difficulty_policy", "Difficulty policy for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "difficulty_window_blocks", "Recent interval window for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "min_solve_time_s", "Minimum solve-time bound for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "max_solve_time_s", "Maximum solve-time bound for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "solver_parallelism", "Solver parallelism field for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "solver_duty_cycle_pct", "Solver duty-cycle field for getmatmulservicechallenge"},
                            }},
                        }},
                        {RPCResult::Type::ANY, "recommended_profile", "Closest built-in profile match shaped like getmatmulservicechallengeprofile.profile plus objective_gap"},
                        {RPCResult::Type::ARR, "candidate_profiles", "All built-in profile matches sorted by closest objective fit", {
                            {RPCResult::Type::ANY, "", "Candidate profile shaped like recommended_profile"},
                        }},
                        {RPCResult::Type::ANY, "challenge_profile", "Resolved challenge profile shaped like getmatmulchallengeprofile"},
                    },
                },
                RPCExamples{
                    HelpExampleCli(
                        MATMUL_SERVICE_CHALLENGE_PLAN_RPC,
                        "\"solves_per_hour\" 600 0.25 0.75")
                    + HelpExampleCli(
                        MATMUL_SERVICE_CHALLENGE_PLAN_RPC,
                        "\"mean_seconds_between_solves\" 12 0.25 0.75 \"adaptive_window\" 24 0.25 30 2 35")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string objective_mode = request.params[0].get_str();
    const double objective_value = request.params[1].get_real();
    const double validation_overhead_s =
        request.params[2].isNull() ? 0.0 : request.params[2].get_real();
    const double propagation_overhead_s =
        request.params[3].isNull() ? 0.0 : request.params[3].get_real();
    const std::string difficulty_policy =
        request.params[4].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED : request.params[4].get_str();
    const int difficulty_window_blocks =
        request.params[5].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_DEFAULT_WINDOW_BLOCKS : request.params[5].getInt<int>();
    const double min_solve_time_s =
        request.params[6].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MIN_SOLVE_TIME_S : request.params[6].get_real();
    const double max_solve_time_s =
        request.params[7].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MAX_SOLVE_TIME_S : request.params[7].get_real();
    const int solver_parallelism =
        request.params[8].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM : request.params[8].getInt<int>();
    const double solver_duty_cycle_pct =
        request.params[9].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT : request.params[9].get_real();
    if (validation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "validation_overhead_s must be non-negative");
    }
    if (propagation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "propagation_overhead_s must be non-negative");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulServiceChallengePlanResponse(
        chainman,
        node,
        objective_mode,
        objective_value,
        validation_overhead_s,
        propagation_overhead_s,
        difficulty_policy,
        difficulty_window_blocks,
        min_solve_time_s,
        max_solve_time_s,
        solver_parallelism,
        solver_duty_cycle_pct);
},
    };
}

static RPCHelpMan getmatmulservicechallengeprofile()
{
    return RPCHelpMan{MATMUL_SERVICE_CHALLENGE_PROFILE_RPC,
                "\nReturns a network-relative MatMul service challenge profile for agentic or application-side gating.\n",
                {
                    {"profile_name", RPCArg::Type::STR, RPCArg::Default{"balanced"}, "Service difficulty profile: interactive, balanced, strict, or background"},
                    {"validation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated validation overhead in seconds"},
                    {"propagation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated propagation overhead in seconds"},
                    {"min_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{0.25}, "Minimum solve-time target allowed after applying the profile ratio"},
                    {"max_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{30}, "Maximum solve-time target allowed after applying the profile ratio"},
                    {"solve_time_multiplier", RPCArg::Type::NUM, RPCArg::Default{1}, "Additional multiplier applied on top of the selected profile's network-relative ratio"},
                    {"difficulty_policy", RPCArg::Type::STR, RPCArg::Default{"fixed"}, "Difficulty policy used for the ready-to-issue defaults: fixed or adaptive_window"},
                    {"difficulty_window_blocks", RPCArg::Type::NUM, RPCArg::Default{24}, "Recent block window used when difficulty_policy=adaptive_window"},
                    {"solver_parallelism", RPCArg::Type::NUM, RPCArg::Default{1}, "Expected number of independent solver workers on the client or gateway tier"},
                    {"solver_duty_cycle_pct", RPCArg::Type::NUM, RPCArg::Default{100}, "Expected share of wall-clock time those workers may use"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "profile", "Resolved service-difficulty recommendation and ready-to-issue defaults", {
                            {RPCResult::Type::STR, "name", "Resolved profile name"},
                            {RPCResult::Type::STR, "difficulty_label", "Short operator-facing difficulty alias: easy, normal, hard, or idle"},
                            {RPCResult::Type::NUM, "effort_tier", "Ascending effort tier for the returned profile"},
                            {RPCResult::Type::STR, "description", "Human-readable profile intent"},
                            {RPCResult::Type::NUM, "network_target_s", "Current network target spacing in seconds"},
                                {RPCResult::Type::NUM, "network_target_ratio", "Profile solve-time ratio applied against the network target"},
                                {RPCResult::Type::NUM, "solve_time_multiplier", "Additional multiplier applied to the profile ratio"},
                                {RPCResult::Type::NUM, "unclamped_target_solve_time_s", "Solve-time target before min/max clamping"},
                                {RPCResult::Type::NUM, "recommended_target_solve_time_s", "Solve-time target after applying min/max clamping"},
                                {RPCResult::Type::NUM, "resolved_target_solve_time_s", "Solve-time target after applying the difficulty policy"},
                                {RPCResult::Type::NUM, "min_solve_time_s", "Minimum solve-time target allowed by the request"},
                                {RPCResult::Type::NUM, "max_solve_time_s", "Maximum solve-time target allowed by the request"},
                                {RPCResult::Type::BOOL, "clamped", "Whether min/max clamping changed the requested target"},
                                {RPCResult::Type::NUM, "estimated_average_node_solve_time_s", "Estimated solve time for an average node after applying the difficulty policy"},
                                {RPCResult::Type::NUM, "estimated_average_node_total_time_s", "Estimated solve time plus validation/propagation overheads"},
                                {RPCResult::Type::NUM, "estimated_average_node_challenges_per_hour", "Estimated completed challenges per hour for an average node"},
                                {RPCResult::Type::OBJ, "operator_capacity", "Average-node capacity estimate scaled by solver_parallelism and solver_duty_cycle_pct", {
                                    {RPCResult::Type::STR, "estimation_basis", "Reference model used by the estimate"},
                                    {RPCResult::Type::NUM, "solver_parallelism", "Requested independent solver workers"},
                                    {RPCResult::Type::NUM, "solver_duty_cycle_pct", "Requested solver duty cycle percentage"},
                                    {RPCResult::Type::NUM, "effective_parallelism", "solver_parallelism scaled by solver_duty_cycle_pct"},
                                    {RPCResult::Type::NUM, "budgeted_solver_seconds_per_hour", "Budgeted solver-seconds per wall-clock hour"},
                                    {RPCResult::Type::NUM, "estimated_sustained_solves_per_hour", "Estimated sustained solves per hour under the requested budget"},
                                    {RPCResult::Type::NUM, "estimated_sustained_solves_per_day", "Estimated sustained solves per day under the requested budget"},
                                    {RPCResult::Type::NUM, "estimated_mean_seconds_between_solves", "Estimated mean wall-clock seconds between completed solves"},
                                }},
                                {RPCResult::Type::OBJ, "difficulty_resolution", "Resolved difficulty policy for the ready-to-issue defaults", {
                                    {RPCResult::Type::STR, "mode", "Difficulty policy mode"},
                                    {RPCResult::Type::NUM, "base_solve_time_s", "Base solve-time target before policy resolution"},
                                    {RPCResult::Type::NUM, "adjusted_solve_time_s", "Adaptive solve-time target before clamping"},
                                    {RPCResult::Type::NUM, "resolved_solve_time_s", "Final solve-time target used for issuance"},
                                    {RPCResult::Type::NUM, "min_solve_time_s", "Minimum solve-time bound used by adaptive_window"},
                                    {RPCResult::Type::NUM, "max_solve_time_s", "Maximum solve-time bound used by adaptive_window"},
                                    {RPCResult::Type::NUM, "window_blocks", "Recent interval window used by adaptive_window"},
                                    {RPCResult::Type::NUM, "observed_interval_count", "Observed intervals contributing to the adaptive resolution"},
                                    {RPCResult::Type::NUM, "observed_mean_interval_s", "Observed mean interval from the anchored window"},
                                    {RPCResult::Type::NUM, "network_target_s", "Consensus target spacing in seconds"},
                                    {RPCResult::Type::NUM, "interval_scale", "Observed mean interval divided by the consensus target spacing"},
                                    {RPCResult::Type::BOOL, "clamped", "Whether adaptive resolution was clamped to the configured bounds"},
                                }},
                                {RPCResult::Type::OBJ, "issue_defaults", "Ready-to-pass defaults for getmatmulservicechallenge", {
                                {RPCResult::Type::STR, "rpc", "Challenge-issuance RPC name"},
                                {RPCResult::Type::STR, "profile_name", "Canonical profile name"},
                                {RPCResult::Type::STR, "difficulty_label", "Short difficulty alias"},
                                {RPCResult::Type::NUM, "target_solve_time_s", "Recommended solve-time target for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "resolved_target_solve_time_s", "Expected resolved solve-time target after applying the difficulty policy"},
                                {RPCResult::Type::NUM, "validation_overhead_s", "Recommended validation overhead field for getmatmulservicechallenge"},
                                {RPCResult::Type::NUM, "propagation_overhead_s", "Recommended propagation overhead field for getmatmulservicechallenge"},
                                {RPCResult::Type::STR, "difficulty_policy", "Difficulty policy for getmatmulservicechallenge"},
                                    {RPCResult::Type::NUM, "difficulty_window_blocks", "Recent interval window for getmatmulservicechallenge"},
                                    {RPCResult::Type::NUM, "min_solve_time_s", "Minimum solve-time bound for getmatmulservicechallenge"},
                                    {RPCResult::Type::NUM, "max_solve_time_s", "Maximum solve-time bound for getmatmulservicechallenge"},
                                    {RPCResult::Type::NUM, "solver_parallelism", "Recommended solver_parallelism field for getmatmulservicechallenge"},
                                    {RPCResult::Type::NUM, "solver_duty_cycle_pct", "Recommended solver_duty_cycle_pct field for getmatmulservicechallenge"},
                                }},
                                {RPCResult::Type::OBJ, "profile_issue_defaults", "Ready-to-pass defaults for issuematmulservicechallengeprofile", {
                                    {RPCResult::Type::STR, "rpc", "Profile-based challenge issuance RPC name"},
                                    {RPCResult::Type::STR, "profile_name", "Canonical profile name"},
                                    {RPCResult::Type::STR, "difficulty_label", "Short difficulty alias"},
                                    {RPCResult::Type::NUM, "resolved_target_solve_time_s", "Expected resolved solve-time target after applying the difficulty policy"},
                                    {RPCResult::Type::NUM, "validation_overhead_s", "Recommended validation overhead field"},
                                    {RPCResult::Type::NUM, "propagation_overhead_s", "Recommended propagation overhead field"},
                                    {RPCResult::Type::NUM, "min_solve_time_s", "Minimum solve-time bound"},
                                    {RPCResult::Type::NUM, "max_solve_time_s", "Maximum solve-time bound"},
                                    {RPCResult::Type::NUM, "solve_time_multiplier", "Multiplier applied on top of the profile ratio"},
                                    {RPCResult::Type::STR, "difficulty_policy", "Difficulty policy for profile-based issuance"},
                                    {RPCResult::Type::NUM, "difficulty_window_blocks", "Recent interval window for profile-based issuance"},
                                    {RPCResult::Type::NUM, "solver_parallelism", "Recommended solver_parallelism field for profile-based issuance"},
                                    {RPCResult::Type::NUM, "solver_duty_cycle_pct", "Recommended solver_duty_cycle_pct field for profile-based issuance"},
                                }},
                            }},
                        {RPCResult::Type::ANY, "challenge_profile", "MatMul challenge profile at the recommended solve-time target, shaped like getmatmulchallengeprofile"},
                    },
                },
                RPCExamples{
                    HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILE_RPC, "")
                    + HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILE_RPC, "\"interactive\" 0.25 0.75")
                    + HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILE_RPC, "\"background\" 0 0 1 45 1.5")
                    + HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILE_RPC, "\"balanced\" 0.25 0.75 0.25 6 1 \"adaptive_window\" 24")
                    + HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILE_RPC, "\"background\" 0.25 0.75 0.25 6 1 \"adaptive_window\" 24 4 35")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string profile_name =
        request.params[0].isNull() ? "balanced" : request.params[0].get_str();
    const double validation_overhead_s =
        request.params[1].isNull() ? 0.0 : request.params[1].get_real();
    const double propagation_overhead_s =
        request.params[2].isNull() ? 0.0 : request.params[2].get_real();
    const double min_solve_time_s =
        request.params[3].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MIN_SOLVE_TIME_S : request.params[3].get_real();
    const double max_solve_time_s =
        request.params[4].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MAX_SOLVE_TIME_S : request.params[4].get_real();
    const double solve_time_multiplier =
        request.params[5].isNull() ? 1.0 : request.params[5].get_real();
    const std::string difficulty_policy =
        request.params[6].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED : request.params[6].get_str();
    const int difficulty_window_blocks =
        request.params[7].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_DEFAULT_WINDOW_BLOCKS : request.params[7].getInt<int>();
    const int solver_parallelism =
        request.params[8].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM : request.params[8].getInt<int>();
    const double solver_duty_cycle_pct =
        request.params[9].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT : request.params[9].get_real();
    if (validation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "validation_overhead_s must be non-negative");
    }
    if (propagation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "propagation_overhead_s must be non-negative");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulServiceChallengeProfileResponse(
        chainman,
        node,
        profile_name,
        validation_overhead_s,
        propagation_overhead_s,
        min_solve_time_s,
        max_solve_time_s,
        solve_time_multiplier,
        difficulty_policy,
        difficulty_window_blocks,
        solver_parallelism,
        solver_duty_cycle_pct);
},
    };
}

static RPCHelpMan listmatmulservicechallengeprofiles()
{
    return RPCHelpMan{MATMUL_SERVICE_CHALLENGE_PROFILES_RPC,
                "\nLists all built-in MatMul service challenge profiles with current network-relative recommendations for average nodes.\n",
                {
                    {"validation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated validation overhead in seconds"},
                    {"propagation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated propagation overhead in seconds"},
                    {"min_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{0.25}, "Minimum solve-time target allowed after applying the profile ratio"},
                    {"max_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{30}, "Maximum solve-time target allowed after applying the profile ratio"},
                    {"solve_time_multiplier", RPCArg::Type::NUM, RPCArg::Default{1}, "Additional multiplier applied on top of the profile ratios"},
                    {"difficulty_policy", RPCArg::Type::STR, RPCArg::Default{"fixed"}, "Difficulty policy used for the ready-to-issue defaults: fixed or adaptive_window"},
                    {"difficulty_window_blocks", RPCArg::Type::NUM, RPCArg::Default{24}, "Recent block window used when difficulty_policy=adaptive_window"},
                    {"solver_parallelism", RPCArg::Type::NUM, RPCArg::Default{1}, "Expected number of independent solver workers on the client or gateway tier"},
                    {"solver_duty_cycle_pct", RPCArg::Type::NUM, RPCArg::Default{100}, "Expected share of wall-clock time those workers may use"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "default_profile", "Default canonical profile name"},
                        {RPCResult::Type::STR, "default_difficulty_label", "Default short difficulty alias"},
                        {RPCResult::Type::ARR, "profiles", "Current profile catalog", {
                            {RPCResult::Type::ANY, "", "Profile entry shaped like getmatmulservicechallengeprofile.profile"},
                        }},
                    },
                },
                RPCExamples{
                    HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILES_RPC, "")
                    + HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILES_RPC, "0.25 0.75 0.25 6 1 \"adaptive_window\" 24")
                    + HelpExampleCli(MATMUL_SERVICE_CHALLENGE_PROFILES_RPC, "0.25 0.75 0.25 6 1 \"adaptive_window\" 24 4 35")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const double validation_overhead_s =
        request.params[0].isNull() ? 0.0 : request.params[0].get_real();
    const double propagation_overhead_s =
        request.params[1].isNull() ? 0.0 : request.params[1].get_real();
    const double min_solve_time_s =
        request.params[2].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MIN_SOLVE_TIME_S : request.params[2].get_real();
    const double max_solve_time_s =
        request.params[3].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MAX_SOLVE_TIME_S : request.params[3].get_real();
    const double solve_time_multiplier =
        request.params[4].isNull() ? 1.0 : request.params[4].get_real();
    const std::string difficulty_policy =
        request.params[5].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED : request.params[5].get_str();
    const int difficulty_window_blocks =
        request.params[6].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_DEFAULT_WINDOW_BLOCKS : request.params[6].getInt<int>();
    const int solver_parallelism =
        request.params[7].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM : request.params[7].getInt<int>();
    const double solver_duty_cycle_pct =
        request.params[8].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT : request.params[8].get_real();
    if (validation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "validation_overhead_s must be non-negative");
    }
    if (propagation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "propagation_overhead_s must be non-negative");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulServiceChallengeProfilesResponse(
        chainman,
        validation_overhead_s,
        propagation_overhead_s,
        min_solve_time_s,
        max_solve_time_s,
        solve_time_multiplier,
        difficulty_policy,
        difficulty_window_blocks,
        solver_parallelism,
        solver_duty_cycle_pct);
},
    };
}

static RPCHelpMan issuematmulservicechallengeprofile()
{
    return RPCHelpMan{"issuematmulservicechallengeprofile",
                "\nIssues a domain-bound MatMul service challenge from a named difficulty profile or short difficulty alias.\n",
                {
                    {"purpose", RPCArg::Type::STR, RPCArg::Optional::NO, "Application policy label, for example rate_limit"},
                    {"resource", RPCArg::Type::STR, RPCArg::Optional::NO, "Bound resource identifier, for example signup:/v1/messages"},
                    {"subject", RPCArg::Type::STR, RPCArg::Optional::NO, "Bound subject identifier, for example user:alice@example.com"},
                    {"profile_name", RPCArg::Type::STR, RPCArg::Default{"balanced"}, "Service difficulty profile or alias: interactive/easy, balanced/normal, strict/hard, or background/idle"},
                    {"expires_in_s", RPCArg::Type::NUM, RPCArg::Default{300}, "Challenge lifetime in seconds"},
                    {"validation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated validation overhead in seconds"},
                    {"propagation_overhead_s", RPCArg::Type::NUM, RPCArg::Default{0}, "Estimated propagation overhead in seconds"},
                    {"min_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{0.25}, "Minimum solve-time target allowed after applying the profile ratio"},
                    {"max_solve_time_s", RPCArg::Type::NUM, RPCArg::Default{30}, "Maximum solve-time target allowed after applying the profile ratio"},
                    {"solve_time_multiplier", RPCArg::Type::NUM, RPCArg::Default{1}, "Additional multiplier applied on top of the selected profile's network-relative ratio"},
                    {"difficulty_policy", RPCArg::Type::STR, RPCArg::Default{"fixed"}, "Difficulty policy used for the issued challenge: fixed or adaptive_window"},
                    {"difficulty_window_blocks", RPCArg::Type::NUM, RPCArg::Default{24}, "Recent block window used when difficulty_policy=adaptive_window"},
                    {"solver_parallelism", RPCArg::Type::NUM, RPCArg::Default{1}, "Expected number of independent solver workers on the client or gateway tier"},
                    {"solver_duty_cycle_pct", RPCArg::Type::NUM, RPCArg::Default{100}, "Expected share of wall-clock time those workers may use"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ANY, "profile", "Resolved profile recommendation shaped like getmatmulservicechallengeprofile.profile"},
                        {RPCResult::Type::ANY, "service_challenge", "Issued challenge envelope shaped like getmatmulservicechallenge"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("issuematmulservicechallengeprofile", "\"rate_limit\" \"signup:/v1/messages\" \"user:alice@example.com\" \"normal\"")
                    + HelpExampleCli("issuematmulservicechallengeprofile", "\"rate_limit\" \"signup:/v1/messages\" \"user:alice@example.com\" \"hard\" 300 0.25 0.75 0.25 6 1 \"adaptive_window\" 24")
                    + HelpExampleCli("issuematmulservicechallengeprofile", "\"rate_limit\" \"signup:/v1/messages\" \"user:alice@example.com\" \"idle\" 300 0.25 0.75 0.25 6 1 \"adaptive_window\" 24 4 35")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string purpose = request.params[0].get_str();
    const std::string resource = request.params[1].get_str();
    const std::string subject = request.params[2].get_str();
    const std::string profile_name =
        request.params[3].isNull() ? "balanced" : request.params[3].get_str();
    const int64_t expires_in_s = request.params[4].isNull() ? 300 : request.params[4].getInt<int64_t>();
    const double validation_overhead_s =
        request.params[5].isNull() ? 0.0 : request.params[5].get_real();
    const double propagation_overhead_s =
        request.params[6].isNull() ? 0.0 : request.params[6].get_real();
    const double min_solve_time_s =
        request.params[7].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MIN_SOLVE_TIME_S : request.params[7].get_real();
    const double max_solve_time_s =
        request.params[8].isNull() ? MATMUL_SERVICE_PROFILE_DEFAULT_MAX_SOLVE_TIME_S : request.params[8].get_real();
    const double solve_time_multiplier =
        request.params[9].isNull() ? 1.0 : request.params[9].get_real();
    const std::string difficulty_policy =
        request.params[10].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_FIXED : request.params[10].get_str();
    const int difficulty_window_blocks =
        request.params[11].isNull() ? MATMUL_SERVICE_DIFFICULTY_POLICY_DEFAULT_WINDOW_BLOCKS : request.params[11].getInt<int>();
    const int solver_parallelism =
        request.params[12].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_PARALLELISM : request.params[12].getInt<int>();
    const double solver_duty_cycle_pct =
        request.params[13].isNull() ? MATMUL_OPERATOR_CAPACITY_DEFAULT_SOLVER_DUTY_CYCLE_PCT : request.params[13].get_real();
    if (expires_in_s < 1 || expires_in_s > MATMUL_SERVICE_MAX_EXPIRY_S) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "expires_in_s must be between 1 and 86400");
    }
    if (validation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "validation_overhead_s must be non-negative");
    }
    if (propagation_overhead_s < 0.0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "propagation_overhead_s must be non-negative");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildIssuedMatMulServiceChallengeProfileResponse(
        chainman,
        node,
        purpose,
        resource,
        subject,
        profile_name,
        expires_in_s,
        validation_overhead_s,
        propagation_overhead_s,
        min_solve_time_s,
        max_solve_time_s,
        solve_time_multiplier,
        difficulty_policy,
        difficulty_window_blocks,
        solver_parallelism,
        solver_duty_cycle_pct);
},
    };
}

static RPCHelpMan solvematmulservicechallenge()
{
    return RPCHelpMan{"solvematmulservicechallenge",
                "\nLocally solves a previously issued MatMul service challenge and returns a proof envelope ready for verification or redemption.\n",
                {
                    {"challenge", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Challenge envelope returned by getmatmulservicechallenge", std::vector<RPCArg>{}},
                    {"max_tries", RPCArg::Type::NUM, RPCArg::Default{500000}, "Maximum nonce attempts before giving up"},
                    {"time_budget_ms", RPCArg::Type::NUM, RPCArg::Default{0}, "Optional wall-clock solve budget in milliseconds; 0 disables time-budget stopping"},
                    {"solver_threads", RPCArg::Type::NUM, RPCArg::Default{0}, "Optional maximum worker threads for the local solver; 0 keeps the normal automatic policy"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "challenge_id", "Challenge identifier"},
                        {RPCResult::Type::BOOL, "solved", "Whether a valid proof was found within max_tries"},
                        {RPCResult::Type::NUM, "attempts", "Nonce attempts consumed while solving"},
                        {RPCResult::Type::NUM, "remaining_tries", "Unused tries left after solving or exhaustion"},
                        {RPCResult::Type::NUM, "elapsed_ms", "Wall-clock solve time in milliseconds"},
                        {RPCResult::Type::NUM, "time_budget_ms", "Requested wall-clock solve budget in milliseconds, or 0 when disabled"},
                        {RPCResult::Type::NUM, "solver_threads", "Requested maximum worker threads, or 0 when the automatic runtime policy is used"},
                        {RPCResult::Type::STR, "reason", "Result code: ok, max_tries_exhausted, or time_budget_exhausted"},
                        {RPCResult::Type::STR_HEX, "nonce64_hex", /*optional=*/true, "Solved nonce when solved=true"},
                        {RPCResult::Type::STR_HEX, "digest_hex", /*optional=*/true, "Solved transcript digest when solved=true"},
                        {RPCResult::Type::ANY, "proof", /*optional=*/true, "Ready-to-submit proof payload when solved=true"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("solvematmulservicechallenge", R"('{"kind":"matmul_service_challenge_v1"}' 500000)")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& challenge_value = request.params[0];
    uint64_t max_tries = request.params[1].isNull() ? 500000 : request.params[1].getInt<uint64_t>();
    if (max_tries == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_tries must be positive");
    }
    const int64_t time_budget_ms =
        request.params[2].isNull() ? 0 : request.params[2].getInt<int64_t>();
    if (time_budget_ms < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "time_budget_ms must be non-negative");
    }
    const int solver_threads =
        request.params[3].isNull() ? 0 : request.params[3].getInt<int>();
    if (solver_threads < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "solver_threads must be non-negative");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }

    const auto ctx = ParseMatMulServiceChallenge(chainman, challenge_value);
    const uint64_t requested_tries = max_tries;
    const auto started_us = GetTime<std::chrono::microseconds>();
    matmul::PowState state = BuildMatMulServicePowState(ctx, 0, uint256{});
    const matmul::PowConfig config = BuildMatMulServicePowConfig(ctx);
    const bool solved = matmul::Solve(
        state,
        config,
        max_tries,
        {
            .time_budget_ms = static_cast<uint64_t>(time_budget_ms),
            .max_worker_threads = static_cast<uint32_t>(solver_threads),
        });
    const double elapsed_ms = static_cast<double>(
        (GetTime<std::chrono::microseconds>() - started_us).count()) / 1000.0;

    UniValue result(UniValue::VOBJ);
    result.pushKV("challenge_id", ctx.challenge_id.GetHex());
    result.pushKV("solved", solved);
    result.pushKV("attempts", requested_tries - max_tries);
    result.pushKV("remaining_tries", max_tries);
    result.pushKV("elapsed_ms", elapsed_ms);
    result.pushKV("time_budget_ms", time_budget_ms);
    result.pushKV("solver_threads", solver_threads);
    if (!solved) {
        result.pushKV(
            "reason",
            time_budget_ms > 0 && max_tries > 0 ? "time_budget_exhausted" : "max_tries_exhausted");
        return result;
    }

    const std::string nonce64_hex = strprintf("%016x", state.nonce);
    const std::string digest_hex = state.digest.GetHex();
    result.pushKV("reason", "ok");
    result.pushKV("nonce64_hex", nonce64_hex);
    result.pushKV("digest_hex", digest_hex);
    UniValue proof(UniValue::VOBJ);
    proof.pushKV("challenge", challenge_value);
    proof.pushKV("nonce64_hex", nonce64_hex);
    proof.pushKV("digest_hex", digest_hex);
    result.pushKV("proof", std::move(proof));
    return result;
},
    };
}

static RPCHelpMan verifymatmulserviceproof()
{
    return RPCHelpMan{"verifymatmulserviceproof",
                "\nVerifies a MatMul service proof against a previously issued challenge envelope.\n",
                {
                    {"challenge", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Challenge envelope returned by getmatmulservicechallenge", std::vector<RPCArg>{}},
                    {"nonce64_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted 64-bit nonce in hexadecimal"},
                    {"digest_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted transcript digest in hexadecimal"},
                    {MATMUL_SERVICE_VERIFY_LOOKUP_LOCAL_STATUS, RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to consult the local/shared issued-challenge registry and include issued/redeemed/redeemable fields. Disable this for stateless high-volume verification."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "challenge_id", "Challenge identifier"},
                        {RPCResult::Type::NUM, "checked_at", "Unix timestamp when verification ran"},
                        {RPCResult::Type::NUM, "expires_at", "Unix expiration timestamp from the challenge"},
                        {RPCResult::Type::BOOL, "local_registry_status_checked", "Whether this result consulted the local/shared issued-challenge registry"},
                        {RPCResult::Type::BOOL, "issued_by_local_node", /*optional=*/true, "Whether this node's configured challenge store recognizes the challenge envelope"},
                        {RPCResult::Type::BOOL, "redeemed", /*optional=*/true, "Whether this node's configured challenge store has already redeemed the challenge"},
                        {RPCResult::Type::BOOL, "redeemable", /*optional=*/true, "Whether the challenge is still redeemable through this node's configured challenge store"},
                        {RPCResult::Type::NUM, "redeemed_at", /*optional=*/true, "Unix timestamp when the challenge was redeemed through this node's configured challenge store"},
                        {RPCResult::Type::BOOL, "valid", "Whether the submitted proof is valid"},
                        {RPCResult::Type::BOOL, "expired", "Whether the challenge expired before verification"},
                        {RPCResult::Type::STR, "reason", "Verification result code"},
                        {RPCResult::Type::STR, "mismatch_field", /*optional=*/true, "Challenge field that failed canonical verification"},
                        {RPCResult::Type::ANY, "proof", /*optional=*/true, "Parsed proof diagnostics"},
                    },
                },
                RPCExamples{
                    HelpExampleCli(
                        "verifymatmulserviceproof",
                        "'{\"kind\":\"matmul_service_challenge_v1\"}' \"0000000000000000\" \"0000000000000000000000000000000000000000000000000000000000000000\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const ArgsManager& args = EnsureArgsman(node);
    const bool include_local_registry_status =
        request.params[3].isNull() ? true : request.params[3].get_bool();
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulServiceProofResult(
        args,
        chainman,
        request.params[0],
        request.params[1].get_str(),
        request.params[2].get_str(),
        include_local_registry_status);
},
    };
}

static RPCHelpMan redeemmatmulserviceproof()
{
    return RPCHelpMan{"redeemmatmulserviceproof",
                "\nVerifies and atomically redeems a locally issued MatMul service proof so applications can enforce one-shot anti-spam or rate-limit gates.\n",
                {
                    {"challenge", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Challenge envelope returned by getmatmulservicechallenge", std::vector<RPCArg>{}},
                    {"nonce64_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted 64-bit nonce in hexadecimal"},
                    {"digest_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted transcript digest in hexadecimal"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "challenge_id", "Challenge identifier"},
                        {RPCResult::Type::NUM, "checked_at", "Unix timestamp when verification ran"},
                        {RPCResult::Type::NUM, "expires_at", "Unix expiration timestamp from the challenge"},
                        {RPCResult::Type::BOOL, "local_registry_status_checked", "Whether this result consulted the local/shared issued-challenge registry"},
                        {RPCResult::Type::BOOL, "issued_by_local_node", "Whether this node's configured challenge store recognizes the challenge envelope"},
                        {RPCResult::Type::BOOL, "redeemed", "Whether this node's configured challenge store has redeemed the challenge"},
                        {RPCResult::Type::BOOL, "redeemable", "Whether the challenge remains redeemable through this node's configured challenge store"},
                        {RPCResult::Type::NUM, "redeemed_at", /*optional=*/true, "Unix timestamp when the challenge was redeemed through this node's configured challenge store"},
                        {RPCResult::Type::BOOL, "valid", "Whether the submitted proof was valid and accepted"},
                        {RPCResult::Type::BOOL, "expired", "Whether the challenge expired before redemption"},
                        {RPCResult::Type::STR, "reason", "Redemption result code"},
                        {RPCResult::Type::STR, "mismatch_field", /*optional=*/true, "Challenge field that failed canonical verification"},
                        {RPCResult::Type::ANY, "proof", /*optional=*/true, "Parsed proof diagnostics"},
                    },
                },
                RPCExamples{
                    HelpExampleCli(
                        "redeemmatmulserviceproof",
                        "'{\"kind\":\"matmul_service_challenge_v1\"}' \"0000000000000000\" \"0000000000000000000000000000000000000000000000000000000000000000\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const ArgsManager& args = EnsureArgsman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }
    return BuildMatMulServiceRedeemResult(
        args,
        chainman,
        request.params[0],
        request.params[1].get_str(),
        request.params[2].get_str());
},
    };
}

static RPCHelpMan verifymatmulserviceproofs()
{
    return RPCHelpMan{"verifymatmulserviceproofs",
                "\nVerifies a batch of MatMul service proofs against previously issued challenge envelopes.\n",
                {
                    {"proofs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of service proofs to verify",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"challenge", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Challenge envelope returned by getmatmulservicechallenge", std::vector<RPCArg>{}},
                                    {"nonce64_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted 64-bit nonce in hexadecimal"},
                                    {"digest_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted transcript digest in hexadecimal"},
                                },
                            },
                        },
                    },
                    {MATMUL_SERVICE_VERIFY_LOOKUP_LOCAL_STATUS, RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to consult the local/shared issued-challenge registry for every proof. Disable for stateless high-volume verification."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "count", "Total proofs processed in the batch"},
                        {RPCResult::Type::NUM, "valid", "Proofs that passed canonical verification"},
                        {RPCResult::Type::NUM, "invalid", "Proofs that failed canonical verification or policy checks"},
                        {RPCResult::Type::OBJ_DYN, "by_reason", "Batch result counts keyed by per-proof reason", {
                            {RPCResult::Type::NUM, "reason", "Number of proofs with this result code"},
                        }},
                        {RPCResult::Type::ARR, "results", "Per-proof verification results in request order", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::NUM, "index", "Original index in the request array"},
                                {RPCResult::Type::STR_HEX, "challenge_id", "Challenge identifier"},
                                {RPCResult::Type::NUM, "checked_at", "Unix timestamp when verification ran"},
                                {RPCResult::Type::NUM, "expires_at", "Unix expiration timestamp from the challenge"},
                                {RPCResult::Type::BOOL, "local_registry_status_checked", "Whether this result consulted the local/shared issued-challenge registry"},
                                {RPCResult::Type::BOOL, "issued_by_local_node", /*optional=*/true, "Whether this node's configured challenge store recognizes the challenge envelope"},
                                {RPCResult::Type::BOOL, "redeemed", /*optional=*/true, "Whether this node's configured challenge store has already redeemed the challenge"},
                                {RPCResult::Type::BOOL, "redeemable", /*optional=*/true, "Whether the challenge is still redeemable through this node's configured challenge store"},
                                {RPCResult::Type::NUM, "redeemed_at", /*optional=*/true, "Unix timestamp when the challenge was redeemed through this node's configured challenge store"},
                                {RPCResult::Type::BOOL, "valid", "Whether the submitted proof is valid"},
                                {RPCResult::Type::BOOL, "expired", "Whether the challenge expired before verification"},
                                {RPCResult::Type::STR, "reason", "Verification result code"},
                                {RPCResult::Type::STR, "mismatch_field", /*optional=*/true, "Challenge field that failed canonical verification"},
                                {RPCResult::Type::ANY, "proof", /*optional=*/true, "Parsed proof diagnostics"},
                            }},
                        }},
                    },
                },
                RPCExamples{
                    HelpExampleCli(
                        "verifymatmulserviceproofs",
                        R"('[{"challenge":{"kind":"matmul_service_challenge_v1"},"nonce64_hex":"0000000000000000","digest_hex":"0000000000000000000000000000000000000000000000000000000000000000"}]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const ArgsManager& args = EnsureArgsman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }

    const auto items = ParseMatMulServiceProofBatchItems(request.params[0]);
    const bool include_local_registry_status =
        request.params[1].isNull() ? true : request.params[1].get_bool();
    return BuildMatMulServiceBatchResult(items, [&](const MatMulServiceProofBatchItem& item) {
        return BuildMatMulServiceProofResult(
            args,
            chainman,
            item.challenge,
            item.nonce64_hex,
            item.digest_hex,
            include_local_registry_status);
    });
},
    };
}

static RPCHelpMan redeemmatmulserviceproofs()
{
    return RPCHelpMan{"redeemmatmulserviceproofs",
                "\nVerifies and sequentially redeems a batch of locally issued MatMul service proofs for one-shot admission-control workflows.\n",
                {
                    {"proofs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of service proofs to redeem",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"challenge", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Challenge envelope returned by getmatmulservicechallenge", std::vector<RPCArg>{}},
                                    {"nonce64_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted 64-bit nonce in hexadecimal"},
                                    {"digest_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Submitted transcript digest in hexadecimal"},
                                },
                            },
                        },
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "count", "Total proofs processed in the batch"},
                        {RPCResult::Type::NUM, "valid", "Proofs that were successfully redeemed"},
                        {RPCResult::Type::NUM, "invalid", "Proofs that failed verification or redemption"},
                        {RPCResult::Type::OBJ_DYN, "by_reason", "Batch result counts keyed by per-proof reason", {
                            {RPCResult::Type::NUM, "reason", "Number of proofs with this result code"},
                        }},
                        {RPCResult::Type::ARR, "results", "Per-proof redemption results in request order", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::NUM, "index", "Original index in the request array"},
                                {RPCResult::Type::STR_HEX, "challenge_id", "Challenge identifier"},
                                {RPCResult::Type::NUM, "checked_at", "Unix timestamp when verification ran"},
                                {RPCResult::Type::NUM, "expires_at", "Unix expiration timestamp from the challenge"},
                                {RPCResult::Type::BOOL, "local_registry_status_checked", "Whether this result consulted the local/shared issued-challenge registry"},
                                {RPCResult::Type::BOOL, "issued_by_local_node", "Whether this node's configured challenge store recognizes the challenge envelope"},
                                {RPCResult::Type::BOOL, "redeemed", "Whether this node's configured challenge store has redeemed the challenge"},
                                {RPCResult::Type::BOOL, "redeemable", "Whether the challenge remains redeemable through this node's configured challenge store"},
                                {RPCResult::Type::NUM, "redeemed_at", /*optional=*/true, "Unix timestamp when the challenge was redeemed through this node's configured challenge store"},
                                {RPCResult::Type::BOOL, "valid", "Whether the submitted proof was valid and accepted"},
                                {RPCResult::Type::BOOL, "expired", "Whether the challenge expired before redemption"},
                                {RPCResult::Type::STR, "reason", "Redemption result code"},
                                {RPCResult::Type::STR, "mismatch_field", /*optional=*/true, "Challenge field that failed canonical verification"},
                                {RPCResult::Type::ANY, "proof", /*optional=*/true, "Parsed proof diagnostics"},
                            }},
                        }},
                    },
                },
                RPCExamples{
                    HelpExampleCli(
                        "redeemmatmulserviceproofs",
                        R"('[{"challenge":{"kind":"matmul_service_challenge_v1"},"nonce64_hex":"0000000000000000","digest_hex":"0000000000000000000000000000000000000000000000000000000000000000"}]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const ArgsManager& args = EnsureArgsman(node);
    if (!chainman.GetConsensus().fMatMulPOW) {
        throw JSONRPCError(RPC_MISC_ERROR, "MatMul proof-of-work is not active on this chain");
    }

    const auto items = ParseMatMulServiceProofBatchItems(request.params[0]);
    return BuildMatMulServiceBatchResult(items, [&](const MatMulServiceProofBatchItem& item) {
        return BuildMatMulServiceRedeemResult(
            args,
            chainman,
            item.challenge,
            item.nonce64_hex,
            item.digest_hex);
    });
},
    };
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
static RPCHelpMan prioritisetransaction()
{
    return RPCHelpMan{"prioritisetransaction",
                "Accepts the transaction into mined blocks at a higher (or lower) priority\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
                    {"priority_delta", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The priority to add or subtract.\n"
            "                  The transaction selection algorithm considers the tx as it would have a higher priority.\n"
            "                  (priority of a transaction is calculated: coinage * value_in_satoshis / txsize)\n"},
                    {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true"},
                RPCExamples{
                    HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    double priority_delta = 0;
    CAmount nAmount = 0;

    if (!request.params[1].isNull()) {
        priority_delta = request.params[1].get_real();
    }
    if (!request.params[2].isNull()) {
        nAmount = request.params[2].getInt<int64_t>();
    }

    CTxMemPool& mempool = EnsureAnyMemPool(request.context);

    // Non-0 fee dust transactions are not allowed for entry, and modification not allowed afterwards
    const auto& tx = mempool.get(hash);
    if (mempool.m_opts.require_standard && tx && !GetDust(*tx, mempool.m_opts.dust_relay_feerate).empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is not supported for transactions with dust outputs.");
    }

    mempool.PrioritiseTransaction(hash, priority_delta, nAmount);
    return true;
},
    };
}

static RPCHelpMan getprioritisedtransactions()
{
    return RPCHelpMan{"getprioritisedtransactions",
        "Returns a map of all user-created (see prioritisetransaction) fee deltas by txid, and whether the tx is present in mempool.",
        {},
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "prioritisation keyed by txid",
            {
                {RPCResult::Type::OBJ, "<transactionid>", "", {
                    {RPCResult::Type::NUM, "fee_delta", "transaction fee delta in satoshis"},
                    {RPCResult::Type::BOOL, "in_mempool", "whether this transaction is currently in mempool"},
                    {RPCResult::Type::NUM, "modified_fee", /*optional=*/true, "modified fee in satoshis. Only returned if in_mempool=true"},
                    {RPCResult::Type::NUM, "priority_delta", /*optional=*/true, "transaction coin-age priority delta"},
                }}
            },
        },
        RPCExamples{
            HelpExampleCli("getprioritisedtransactions", "")
            + HelpExampleRpc("getprioritisedtransactions", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            CTxMemPool& mempool = EnsureMemPool(node);
            UniValue rpc_result{UniValue::VOBJ};
            for (const auto& delta_info : mempool.GetPrioritisedTransactions()) {
                UniValue result_inner{UniValue::VOBJ};
                result_inner.pushKV("fee_delta", delta_info.delta);
                result_inner.pushKV("in_mempool", delta_info.in_mempool);
                if (delta_info.in_mempool) {
                    result_inner.pushKV("modified_fee", *delta_info.modified_fee);
                }
                result_inner.pushKV("priority_delta", delta_info.priority_delta);
                rpc_result.pushKV(delta_info.txid.GetHex(), std::move(result_inner));
            }
            return rpc_result;
        },
    };
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid())
        return UniValue::VNULL;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

static std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

static UniValue TemplateToJSON(
    const Consensus::Params&,
    const ChainstateManager&,
    const BlockTemplate*,
    const CBlockIndex*,
    const std::set<std::string>& setClientRules,
    unsigned int nTransactionsUpdatedLast,
    const BlockAssembler::Options& block_options,
    const node::MiningChainGuardStatus& chain_guard_status);

static RPCHelpMan getblocktemplate()
{
    return RPCHelpMan{"getblocktemplate",
        "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
        "It returns data needed to construct a block to work on.\n"
        "For MatMul PoW networks, the template includes matrix seeds and parameters needed for external mining.\n"
        "External miners should solve the MatMul proof using the provided seeds and submit via submitblock.\n"
        "For full specification, see BIPs 22, 23, 9, and 145:\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki\n",
        {
            {"template_request", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Format of the template",
            {
                {"mode", RPCArg::Type::STR, /* treat as named arg */ RPCArg::Optional::OMITTED, "This must be set to \"template\", \"proposal\" (see BIP 23), or omitted"},
                {"blockmaxsize", RPCArg::Type::NUM, RPCArg::DefaultHint{"set by -blockmaxsize"}, "limit returned block to specified size (disables template cache)"},
                {"blockmaxweight", RPCArg::Type::NUM, RPCArg::DefaultHint{"set by -blockmaxweight"}, "limit returned block to specified weight (disables template cache)"},
                {"blockreservedsigops", RPCArg::Type::NUM, RPCArg::Default{node::BlockCreateOptions{}.coinbase_output_max_additional_sigops}, "reserve specified number of sigops in returned block for generation transaction (disables template cache)"},
                {"blockreservedsize", RPCArg::Type::NUM, RPCArg::Default{node::BlockCreateOptions{}.block_reserved_size}, "reserve specified size in returned block for generation transaction (disables template cache)"},
                {"blockreservedweight", RPCArg::Type::NUM, RPCArg::Default{node::BlockCreateOptions{}.block_reserved_weight}, "reserve specified weight in returned block for generation transaction (disables template cache)"},
                {"capabilities", RPCArg::Type::ARR, /* treat as named arg */ RPCArg::Optional::OMITTED, "A list of strings",
                {
                    {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported feature, 'longpoll', 'coinbasevalue', 'proposal', 'skip_validity_test', 'serverlist', 'workid'"},
                }},
                {"rules", RPCArg::Type::ARR, RPCArg::Optional::NO, "A list of strings",
                {
                    {"segwit", RPCArg::Type::STR, RPCArg::Optional::NO, "(literal) indicates client side segwit support"},
                    {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "other client side supported softfork deployment"},
                }},
                {"longpollid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "delay processing request until the result would vary significantly from the \"longpollid\" of a prior template"},
                {"minfeerate", RPCArg::Type::NUM, RPCArg::DefaultHint{"set by -blockmintxfee"}, "only include transactions with a minimum sats/vbyte (disables template cache)"},
                {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "proposed block data to check, encoded in hexadecimal; valid only for mode=\"proposal\""},
            },
            },
        },
        {
            RPCResult{"If the proposal was accepted with mode=='proposal'", RPCResult::Type::NONE, "", ""},
            RPCResult{"If the proposal was not accepted with mode=='proposal'", RPCResult::Type::STR, "", "According to BIP22"},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "version", "The preferred block version"},
                {RPCResult::Type::ARR, "rules", "specific block rules that are to be enforced",
                {
                    {RPCResult::Type::STR, "", "name of a rule the client must understand to some extent; see BIP 9 for format"},
                }},
                {RPCResult::Type::OBJ_DYN, "vbavailable", "set of pending, supported versionbit (BIP 9) softfork deployments",
                {
                    {RPCResult::Type::NUM, "rulename", "identifies the bit number as indicating acceptance and readiness for the named softfork rule"},
                }},
                {RPCResult::Type::ARR, "capabilities", "",
                {
                    {RPCResult::Type::STR, "value", "A supported feature, for example 'proposal'"},
                }},
                {RPCResult::Type::NUM, "vbrequired", "bit mask of versionbits the server requires set in submissions"},
                {RPCResult::Type::STR, "previousblockhash", "The hash of current highest block"},
                {RPCResult::Type::ARR, "transactions", "contents of non-coinbase transactions that should be included in the next block",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "data", "transaction data encoded in hexadecimal (byte-for-byte)"},
                        {RPCResult::Type::STR_HEX, "txid", "transaction hash excluding witness data, shown in byte-reversed hex"},
                        {RPCResult::Type::STR_HEX, "hash", "transaction hash including witness data, shown in byte-reversed hex"},
                        {RPCResult::Type::ARR, "depends", "array of numbers",
                        {
                            {RPCResult::Type::NUM, "", "transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is"},
                        }},
                        {RPCResult::Type::NUM, "fee", "difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one"},
                        {RPCResult::Type::NUM, "priority", /*optional=*/true, "transaction coin-age priority (non-standard)"},
                        {RPCResult::Type::NUM, "sigops", "total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero"},
                        {RPCResult::Type::NUM, "weight", "total transaction weight, as counted for purposes of block limits"},
                    }},
                }},
                {RPCResult::Type::OBJ_DYN, "coinbaseaux", "data that should be included in the coinbase's scriptSig content",
                {
                    {RPCResult::Type::STR_HEX, "key", "values must be in the coinbase (keys may be ignored)"},
                }},
                {RPCResult::Type::NUM, "coinbasevalue", "maximum allowable input to coinbase transaction, including the generation award and transaction fees (in satoshis)"},
                {RPCResult::Type::STR, "longpollid", "an id to include with a request to longpoll on an update to this template"},
                {RPCResult::Type::STR, "target", "The hash target"},
                {RPCResult::Type::NUM_TIME, "mintime", "The minimum timestamp appropriate for the next block time, expressed in " + UNIX_EPOCH_TIME + ". Adjusted for the proposed BIP94 timewarp rule."},
                {RPCResult::Type::ARR, "mutable", "list of ways the block template may be changed",
                {
                    {RPCResult::Type::STR, "value", "A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'"},
                }},
                {RPCResult::Type::STR_HEX, "noncerange", "A range of valid nonces"},
                {RPCResult::Type::NUM, "sigoplimit", "limit of sigops in blocks"},
                {RPCResult::Type::NUM, "sizelimit", "limit of block size"},
                {RPCResult::Type::NUM, "weightlimit", /*optional=*/true, "limit of block weight"},
                {RPCResult::Type::OBJ, "block_capacity", "Consensus and policy block-capacity limits",
                {
                    {RPCResult::Type::NUM, "max_block_weight", "consensus maximum block weight"},
                    {RPCResult::Type::NUM, "max_block_serialized_size", "consensus maximum serialized block size in bytes"},
                    {RPCResult::Type::NUM, "max_block_sigops_cost", "consensus maximum block sigops cost"},
                    {RPCResult::Type::NUM, "default_block_max_weight", "default block template weight target"},
                    {RPCResult::Type::NUM, "policy_block_max_weight", "effective local block template weight target"},
                    {RPCResult::Type::NUM, "max_block_shielded_verify_units", "consensus maximum shielded verification units per block"},
                    {RPCResult::Type::NUM, "max_block_shielded_scan_units", "consensus maximum shielded scan units per block"},
                    {RPCResult::Type::NUM, "max_block_shielded_tree_update_units", "consensus maximum shielded tree-update units per block"},
                    {RPCResult::Type::NUM, "template_shielded_verify_units", "shielded verification units currently used by this block template"},
                    {RPCResult::Type::NUM, "template_shielded_scan_units", "shielded scan units currently used by this block template"},
                    {RPCResult::Type::NUM, "template_shielded_tree_update_units", "shielded tree-update units currently used by this block template"},
                    {RPCResult::Type::NUM, "remaining_shielded_verify_units", "remaining shielded verification units available to this block template"},
                    {RPCResult::Type::NUM, "remaining_shielded_scan_units", "remaining shielded scan units available to this block template"},
                    {RPCResult::Type::NUM, "remaining_shielded_tree_update_units", "remaining shielded tree-update units available to this block template"},
                    {RPCResult::Type::NUM, "witness_scale_factor", "witness serialization scale factor"},
                }},
                {RPCResult::Type::NUM_TIME, "curtime", "current timestamp in " + UNIX_EPOCH_TIME + ". Adjusted for the proposed BIP94 timewarp rule."},
                {RPCResult::Type::STR, "bits", "compressed target of next block"},
                {RPCResult::Type::NUM, "height", "The height of the next block"},
                {RPCResult::Type::OBJ, "matmul", /*optional=*/true, "MatMul mining parameters and seeds",
                {
                    {RPCResult::Type::NUM, "n", "MatMul matrix dimension"},
                    {RPCResult::Type::NUM, "b", "MatMul transcript block size"},
                    {RPCResult::Type::NUM, "r", "MatMul noise rank"},
                    {RPCResult::Type::NUM, "q", "MatMul finite field modulus"},
                    {RPCResult::Type::STR_HEX, "seed_a", "MatMul matrix seed A"},
                    {RPCResult::Type::STR_HEX, "seed_b", "MatMul matrix seed B"},
                    {RPCResult::Type::NUM, "min_dimension", "minimum allowed MatMul matrix dimension"},
                    {RPCResult::Type::NUM, "max_dimension", "maximum allowed MatMul matrix dimension"},
                }},
                {RPCResult::Type::NUM, "matmul_n", /*optional=*/true, "MatMul matrix dimension (n)"},
                {RPCResult::Type::NUM, "matmul_b", /*optional=*/true, "MatMul transcript block size (b)"},
                {RPCResult::Type::NUM, "matmul_r", /*optional=*/true, "MatMul noise rank (r)"},
                {RPCResult::Type::STR_HEX, "seed_a", /*optional=*/true, "MatMul matrix seed A"},
                {RPCResult::Type::STR_HEX, "seed_b", /*optional=*/true, "MatMul matrix seed B"},
                {RPCResult::Type::NUM, "matmul_field_modulus", /*optional=*/true, "MatMul finite field modulus"},
                {RPCResult::Type::NUM, "matmul_min_dimension", /*optional=*/true, "minimum allowed MatMul matrix dimension"},
                {RPCResult::Type::NUM, "matmul_max_dimension", /*optional=*/true, "maximum allowed MatMul matrix dimension"},
                {RPCResult::Type::OBJ, "pq_info", /*optional=*/true, "Post-quantum signature profile",
                {
                    {RPCResult::Type::STR, "pq_algorithm", "primary post-quantum signature algorithm"},
                    {RPCResult::Type::STR, "pq_backup_algorithm", "backup post-quantum signature algorithm"},
                    {RPCResult::Type::NUM, "pq_pubkey_size", "primary public key size in bytes"},
                    {RPCResult::Type::NUM, "pq_signature_size", "primary signature size in bytes"},
                }},
                {RPCResult::Type::OBJ, "chain_guard", "Mining chain-alignment status for external miners",
                {
                    {RPCResult::Type::BOOL, "enabled", "Whether the guard is enabled on this node"},
                    {RPCResult::Type::BOOL, "healthy", "Whether the node currently considers its active tip aligned enough for mining"},
                    {RPCResult::Type::BOOL, "should_pause_mining", "Whether external miners should pause submitting new work"},
                    {RPCResult::Type::STR, "recommended_action", "Recommended miner action: continue, catch_up, or pause"},
                    {RPCResult::Type::STR, "reason", "Current guard decision reason"},
                    {RPCResult::Type::NUM, "local_tip", "Current local active-chain height"},
                    {RPCResult::Type::NUM, "peer_count", "Outbound peers considered for the guard decision"},
                    {RPCResult::Type::NUM, "median_peer_tip", "Median tip height advertised by considered outbound peers, or -1 if unavailable"},
                    {RPCResult::Type::NUM, "best_peer_tip", "Highest tip height advertised by considered outbound peers, or -1 if unavailable"},
                    {RPCResult::Type::NUM, "near_tip_peers", "Considered outbound peers within the near-tip window of the local tip"},
                }},
                {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "Only on signet"},
                {RPCResult::Type::STR_HEX, "default_witness_commitment", /*optional=*/true, "a valid witness commitment for the unmodified block template"},
            }},
        },
        RPCExamples{
                    HelpExampleCli("getblocktemplate", "'{\"rules\": [\"segwit\"]}'")
            + HelpExampleRpc("getblocktemplate", "{\"rules\": [\"segwit\"]}")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    Mining& miner = EnsureMining(node);
    LOCK(cs_main);
    uint256 tip{CHECK_NONFATAL(miner.getTip()).value().hash};

    BlockAssembler::Options options;
    {
        const ArgsManager& args{EnsureAnyArgsman(request.context)};
        ApplyArgsManOptions(args, options);
    }
    const BlockAssembler::Options options_def{options.Clamped()};
    bool bypass_cache{false};

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = oparam.find_value("mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = oparam.find_value("longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = oparam.find_value("data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
            if (pindex) {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != tip) {
                return "inconclusive-not-best-prevblk";
            }
            CBlockIndex* pindex_prev_proposal = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
            if (!pindex_prev_proposal) {
                return "inconclusive-not-best-prevblk";
            }
            BlockValidationState state;
            TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block, pindex_prev_proposal, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = oparam.find_value("rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        }

        if (!oparam["blockmaxsize"].isNull()) {
            options.nBlockMaxSize = oparam["blockmaxsize"].getInt<size_t>();
        }
        if (!oparam["blockmaxweight"].isNull()) {
            options.nBlockMaxWeight = oparam["blockmaxweight"].getInt<size_t>();
        }
        if (!oparam["blockreservedsize"].isNull()) {
            options.block_reserved_size = oparam["blockreservedsize"].getInt<size_t>();
        }
        if (!oparam["blockreservedweight"].isNull()) {
            options.block_reserved_weight = oparam["blockreservedweight"].getInt<size_t>();
        }
        if (!oparam["blockreservedsigops"].isNull()) {
            options.coinbase_output_max_additional_sigops = oparam["blockreservedsigops"].getInt<size_t>();
        }
        if (!oparam["minfeerate"].isNull()) {
            options.blockMinFeeRate = CFeeRate{AmountFromValue(oparam["minfeerate"]), COIN /* sat/vB */};
        }
        options = options.Clamped();
        bypass_cache |= !(options == options_def);

        // NOTE: Intentionally not setting bypass_cache for skip_validity_test since _using_ the cache is fine
        const UniValue& client_caps = oparam.find_value("capabilities");
        if (client_caps.isArray()) {
            for (unsigned int i = 0; i < client_caps.size(); ++i) {
                const UniValue& v = client_caps[i];
                if (!v.isStr()) continue;
                if (v.get_str() == "skip_validity_test") {
                    options.test_block_validity = false;
                }
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    const CConnman& connman = EnsureConnman(node);
    const CChainParams& chainparams = chainman.GetParams();
    const ArgsManager& args = EnsureArgsman(node);
    const PeerManager* const peerman = node.peerman.get();
    const int64_t min_outbound_peers = std::max<int64_t>(
        0,
        args.GetIntArg("-miningminoutboundpeers", DefaultMinOutboundPeersForMiningTemplate(chainparams)));
    const int64_t min_synced_outbound_peers = std::max<int64_t>(
        0,
        args.GetIntArg("-miningminsyncedoutboundpeers", DefaultMinSyncedOutboundPeersForMiningTemplate(chainparams)));
    const int64_t max_peer_sync_height_lag = std::max<int64_t>(
        0,
        args.GetIntArg("-miningmaxpeersyncheightlag", DefaultMaxPeerSyncHeightLagForMiningTemplate(chainparams)));
    const int64_t max_header_lag = std::max<int64_t>(
        0,
        args.GetIntArg("-miningmaxheaderlag", DefaultMaxHeaderLagForMiningTemplate(chainparams)));
    const bool enforce_connectivity =
        !miner.isTestChain() || min_outbound_peers > 0 || min_synced_outbound_peers > 0;
    const bool enforce_header_lag =
        !miner.isTestChain() || max_header_lag > 0;

    EnforceMiningTemplateReadiness(
        chainman,
        connman,
        peerman,
        miner,
        enforce_connectivity,
        min_outbound_peers,
        min_synced_outbound_peers,
        max_peer_sync_height_lag,
        enforce_header_lag,
        max_header_lag);

    static unsigned int nTransactionsUpdatedLast;
    const CTxMemPool& mempool = EnsureMemPool(node);

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            const std::string& lpstr = lpval.get_str();

            hashWatchedChain = ParseHashV(lpstr.substr(0, 64), "longpollid");
            nTransactionsUpdatedLastLP = LocaleIndependentAtoi<int64_t>(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = tip;
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            MillisecondsDouble checktxtime{std::chrono::minutes(1)};
            while (tip == hashWatchedChain && IsRPCRunning()) {
                std::optional<BlockRef> maybe_tip{miner.waitTipChanged(hashWatchedChain, checktxtime)};
                // Node is shutting down
                if (!maybe_tip) break;
                tip = maybe_tip->hash;
                // Timeout: Check transactions for update
                // without holding the mempool lock to avoid deadlocks
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                    break;
                checktxtime = std::chrono::seconds(10);
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        tip = CHECK_NONFATAL(miner.getTip()).value().hash;

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // Re-check readiness after longpoll wakeup; connectivity/header-lag
        // may have degraded while waiting.
        EnforceMiningTemplateReadiness(
            chainman,
            connman,
            peerman,
            miner,
            enforce_connectivity,
            min_outbound_peers,
            min_synced_outbound_peers,
            max_peer_sync_height_lag,
            enforce_header_lag,
            max_header_lag);
    }

    const Consensus::Params& consensusParams = chainman.GetParams().GetConsensus();

    // GBT must be called with 'signet' set in the rules for signet chains
    if (consensusParams.signet_blocks && setClientRules.count("signet") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the signet rule set (call with {\"rules\": [\"segwit\", \"signet\"]})");
    }

    // GBT must be called with 'segwit' set in the rules
    if (setClientRules.count("segwit") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
    }
    const auto chain_guard_status = node::GetMiningChainGuardStatus(node);
    const bool pause_external_mining = node::ShouldPauseMiningByChainGuard(chain_guard_status);
    bypass_cache |= pause_external_mining;

    // Update block
    static uint256 pindexPrevHash;
    static int64_t time_start;
    static std::unique_ptr<BlockTemplate> block_template;
    CBlockIndex* cached_pindex_prev = pindexPrevHash.IsNull() ? nullptr : chainman.m_blockman.LookupBlockIndex(pindexPrevHash);
    if (!cached_pindex_prev || pindexPrevHash != tip ||
        bypass_cache ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - time_start > 5))
    {
        if (bypass_cache || !options.test_block_validity) {
            // Create one-off template unrelated to cache
            const auto tx_update_counter = mempool.GetTransactionsUpdated();
            CBlockIndex* const local_pindexPrev = chainman.m_blockman.LookupBlockIndex(tip);
            if (!local_pindexPrev) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "tip block index not found for getblocktemplate");
            }
            options.bypass_chain_guard = pause_external_mining;
            auto tmpl = miner.createNewBlock2(options);
            CHECK_NONFATAL(tmpl);
            return TemplateToJSON(consensusParams, chainman, &*tmpl, local_pindexPrev, setClientRules, tx_update_counter, options, chain_guard_status);
        }
        CHECK_NONFATAL(options == options_def);

        // Clear the cached tip hash so future calls make a new block, despite any failures from here on
        pindexPrevHash.SetNull();

        // Store the pindexBest used before createNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainman.m_blockman.LookupBlockIndex(tip);
        if (!pindexPrevNew) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "tip block index not found while preparing block template");
        }
        time_start = GetTime();

        // Create new block
        block_template = miner.createNewBlock();
        CHECK_NONFATAL(block_template);


        // Need to update only after we know createNewBlock succeeded.
        pindexPrevHash = pindexPrevNew->GetBlockHash();
        cached_pindex_prev = pindexPrevNew;
    }
    CHECK_NONFATAL(cached_pindex_prev);

    return TemplateToJSON(consensusParams, chainman, &*block_template, cached_pindex_prev, setClientRules, nTransactionsUpdatedLast, options_def, chain_guard_status);
},
    };
}

static UniValue TemplateToJSON(
    const Consensus::Params& consensusParams,
    const ChainstateManager& chainman,
    const BlockTemplate* block_template,
    const CBlockIndex* const pindexPrev,
    const std::set<std::string>& setClientRules,
    const unsigned int nTransactionsUpdatedLast,
    const BlockAssembler::Options& block_options,
    const node::MiningChainGuardStatus& chain_guard_status)
{
    CHECK_NONFATAL(block_template);
    CHECK_NONFATAL(pindexPrev);
    const CBlock& block = block_template->getBlock();

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
    const bool fPreSegWit = !DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_SEGWIT);

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    const std::vector<CAmount>& tx_fees{block_template->getTxFees()};
    const std::vector<CAmount>& tx_sigops{block_template->getTxSigops()};
    const std::vector<double>& tx_coin_age_priorities{block_template->getTxCoinAgePriorities()};

    int i = 0;
    for (const auto& it : block.vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));
        entry.pushKV("txid", txHash.GetHex());
        entry.pushKV("hash", tx.GetWitnessHash().GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", std::move(deps));

        int index_in_template = i - 1;
        entry.pushKV("fee", tx_fees.at(index_in_template));
        int64_t nTxSigOps{tx_sigops.at(index_in_template)};
        if (fPreSegWit) {
            CHECK_NONFATAL(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.pushKV("sigops", nTxSigOps);
        entry.pushKV("weight", GetTransactionWeight(tx));
        if (index_in_template && !tx_coin_age_priorities.empty()) {
            entry.pushKV("priority", tx_coin_age_priorities.at(index_in_template));
        }

        transactions.push_back(std::move(entry));
    }

    UniValue aux(UniValue::VOBJ);

    CBlockHeader block_header{block};
    int next_height{0};
    if (!TryGetNextBlockHeight(pindexPrev, next_height)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "next block height overflow");
    }
    // Update nTime (and potentially nBits)
    UpdateTime(&block_header, consensusParams, pindexPrev);
    block_header.nNonce = 0;
    block_header.nNonce64 = 0;
    block_header.mix_hash.SetNull();
    if (consensusParams.fMatMulPOW) {
        block_header.matmul_digest.SetNull();
    }

    if (IsThisSoftwareExpired(block_header.nTime)) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "node software has expired");
    }

    arith_uint256 hashTarget = arith_uint256().SetCompact(block_header.nBits);
    const bool kawpow_active = consensusParams.fKAWPOW && next_height >= consensusParams.nKAWPOWHeight;
    const bool matmul_active = consensusParams.fMatMulPOW;

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");
    if (matmul_active) {
        aMutable.push_back("nonce64");
        // Seeds are NOT mutable: they are deterministically derived from
        // hashPrevBlock and height. Marking them mutable would signal to pool
        // software (via BIP22) that seeds can be freely modified.
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", std::move(aCaps));
    result.pushKV("chain_guard", MiningChainGuardToJSON(chain_guard_status));

    UniValue aRules(UniValue::VARR);
    aRules.push_back("csv");
    if (!fPreSegWit) aRules.push_back("!segwit");
    if (consensusParams.signet_blocks) {
        // indicate to miner that they must understand signet rules
        // when attempting to mine with this template
        aRules.push_back("!signet");
    }

    UniValue vbavailable(UniValue::VOBJ);
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = chainman.m_versionbitscache.State(pindexPrev, consensusParams, pos);
        switch (state) {
            case ThresholdState::DEFINED:
            case ThresholdState::FAILED:
                // Not exposed to GBT at all
                break;
            case ThresholdState::LOCKED_IN:
                // Ensure bit is set in block version
                block_header.nVersion |= chainman.m_versionbitscache.Mask(consensusParams, pos);
                [[fallthrough]];
            case ThresholdState::STARTED:
            {
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.pushKV(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit);
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        block_header.nVersion &= ~chainman.m_versionbitscache.Mask(consensusParams, pos);
                    }
                }
                break;
            }
            case ThresholdState::ACTIVE:
            {
                // Add to rules only
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    result.pushKV("version", block_header.nVersion);
    result.pushKV("rules", std::move(aRules));
    result.pushKV("vbavailable", std::move(vbavailable));
    result.pushKV("vbrequired", int(0));

    result.pushKV("previousblockhash", block.hashPrevBlock.GetHex());
    result.pushKV("transactions", std::move(transactions));
    result.pushKV("coinbaseaux", std::move(aux));
    CHECK_NONFATAL(!block.vtx[0]->vout.empty());
    result.pushKV("coinbasevalue", (int64_t)block.vtx[0]->vout[0].nValue);
    result.pushKV("longpollid", pindexPrev->GetBlockHash().GetHex() + ToString(nTransactionsUpdatedLast));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", GetMinimumTime(pindexPrev, consensusParams));
    result.pushKV("mutable", std::move(aMutable));
    result.pushKV("noncerange", (kawpow_active || matmul_active) ? "0000000000000000ffffffffffffffff" : "00000000ffffffff");
    const uint64_t template_shielded_verify_units = block_template->getShieldedVerifyUnits();
    const uint64_t template_shielded_scan_units = block_template->getShieldedScanUnits();
    const uint64_t template_shielded_tree_update_units = block_template->getShieldedTreeUpdateUnits();
    UniValue block_capacity(UniValue::VOBJ);
    block_capacity.pushKV("max_block_weight", static_cast<int64_t>(MAX_BLOCK_WEIGHT));
    block_capacity.pushKV("max_block_serialized_size", static_cast<int64_t>(MAX_BLOCK_SERIALIZED_SIZE));
    block_capacity.pushKV("max_block_sigops_cost", static_cast<int64_t>(MAX_BLOCK_SIGOPS_COST));
    block_capacity.pushKV("default_block_max_weight", static_cast<int64_t>(BlockAssembler::Options{}.nBlockMaxWeight));
    block_capacity.pushKV("policy_block_max_weight", static_cast<int64_t>(block_options.nBlockMaxWeight));
    block_capacity.pushKV("max_block_shielded_verify_units", static_cast<int64_t>(consensusParams.nMaxBlockShieldedVerifyCost));
    block_capacity.pushKV("max_block_shielded_scan_units", static_cast<int64_t>(consensusParams.nMaxBlockShieldedScanUnits));
    block_capacity.pushKV("max_block_shielded_tree_update_units", static_cast<int64_t>(consensusParams.nMaxBlockShieldedTreeUpdateUnits));
    block_capacity.pushKV("template_shielded_verify_units", static_cast<int64_t>(template_shielded_verify_units));
    block_capacity.pushKV("template_shielded_scan_units", static_cast<int64_t>(template_shielded_scan_units));
    block_capacity.pushKV("template_shielded_tree_update_units", static_cast<int64_t>(template_shielded_tree_update_units));
    block_capacity.pushKV("remaining_shielded_verify_units", static_cast<int64_t>(template_shielded_verify_units <= consensusParams.nMaxBlockShieldedVerifyCost ? consensusParams.nMaxBlockShieldedVerifyCost - template_shielded_verify_units : 0));
    block_capacity.pushKV("remaining_shielded_scan_units", static_cast<int64_t>(template_shielded_scan_units <= consensusParams.nMaxBlockShieldedScanUnits ? consensusParams.nMaxBlockShieldedScanUnits - template_shielded_scan_units : 0));
    block_capacity.pushKV("remaining_shielded_tree_update_units", static_cast<int64_t>(template_shielded_tree_update_units <= consensusParams.nMaxBlockShieldedTreeUpdateUnits ? consensusParams.nMaxBlockShieldedTreeUpdateUnits - template_shielded_tree_update_units : 0));
    block_capacity.pushKV("witness_scale_factor", static_cast<int64_t>(WITNESS_SCALE_FACTOR));
    result.pushKV("block_capacity", std::move(block_capacity));
    int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
    int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
    if (fPreSegWit) {
        CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
        CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
        nSizeLimit /= WITNESS_SCALE_FACTOR;
    }
    result.pushKV("sigoplimit", nSigOpLimit);
    result.pushKV("sizelimit", nSizeLimit);
    if (!fPreSegWit) {
        result.pushKV("weightlimit", (int64_t)MAX_BLOCK_WEIGHT);
    }
    result.pushKV("curtime", block_header.GetBlockTime());
    result.pushKV("bits", strprintf("%08x", block_header.nBits));
    result.pushKV("height", static_cast<int64_t>(next_height));
    if (matmul_active) {
        UniValue matmul(UniValue::VOBJ);
        matmul.pushKV("n", block_header.matmul_dim);
        matmul.pushKV("b", consensusParams.nMatMulTranscriptBlockSize);
        matmul.pushKV("r", consensusParams.nMatMulNoiseRank);
        matmul.pushKV("q", static_cast<uint64_t>(consensusParams.nMatMulFieldModulus));
        matmul.pushKV("seed_a", block_header.seed_a.GetHex());
        matmul.pushKV("seed_b", block_header.seed_b.GetHex());
        matmul.pushKV("min_dimension", static_cast<uint64_t>(consensusParams.nMatMulMinDimension));
        matmul.pushKV("max_dimension", static_cast<uint64_t>(consensusParams.nMatMulMaxDimension));
        result.pushKV("matmul", std::move(matmul));

        // Backward-compatible top-level fields retained for existing miners/tests.
        result.pushKV("matmul_n", block_header.matmul_dim);
        result.pushKV("matmul_b", consensusParams.nMatMulTranscriptBlockSize);
        result.pushKV("matmul_r", consensusParams.nMatMulNoiseRank);
        result.pushKV("seed_a", block_header.seed_a.GetHex());
        result.pushKV("seed_b", block_header.seed_b.GetHex());
        result.pushKV("matmul_field_modulus", (uint64_t)consensusParams.nMatMulFieldModulus);
        result.pushKV("matmul_min_dimension", static_cast<uint64_t>(consensusParams.nMatMulMinDimension));
        result.pushKV("matmul_max_dimension", static_cast<uint64_t>(consensusParams.nMatMulMaxDimension));

        UniValue pq_info(UniValue::VOBJ);
        pq_info.pushKV("pq_algorithm", "ml-dsa-44");
        pq_info.pushKV("pq_backup_algorithm", "slh-dsa-shake-128s");
        pq_info.pushKV("pq_pubkey_size", static_cast<uint64_t>(MLDSA44_PUBKEY_SIZE));
        pq_info.pushKV("pq_signature_size", static_cast<uint64_t>(MLDSA44_SIGNATURE_SIZE));
        result.pushKV("pq_info", std::move(pq_info));
    }

    if (consensusParams.signet_blocks) {
        result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
    }

    if (!block_template->getCoinbaseCommitment().empty()) {
        result.pushKV("default_witness_commitment", HexStr(block_template->getCoinbaseCommitment()));
    }

    return result;
}

class submitblock_StateCatcher final : public CValidationInterface
{
public:
    uint256 hash;
    bool found{false};
    BlockValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), state() {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static RPCHelpMan submitblock()
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    return RPCHelpMan{"submitblock",
        "\nAttempts to submit new block to network.\n"
        "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n",
        {
            {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
            {"dummy", RPCArg::Type::STR, RPCArg::DefaultHint{"ignored"}, "dummy value, for compatibility with BIP22. This value is ignored."},
        },
        {
            RPCResult{"If the block was accepted", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::STR, "", "According to BIP22"},
        },
        RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    const auto chain_guard_status = node::GetMiningChainGuardStatus(node);
    if (node::ShouldPauseMiningByChainGuard(chain_guard_status)) {
        return strprintf("paused-chain-guard-%s", node::GetMiningChainGuardRecommendedAction(chain_guard_status));
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
        if (pindex) {
            chainman.UpdateUncommittedBlockStructures(block, pindex);
        }
    }

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);
    bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);
    if (!new_block && accepted) {
        return "duplicate";
    }
    if (!sc->found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc->state);
},
    };
}

static RPCHelpMan submitheader()
{
    return RPCHelpMan{"submitheader",
                "\nDecode the given hexdata as a header and submit it as a candidate chain tip if valid."
                "\nThrows when the header is invalid.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block header data"},
                },
                RPCResult{
                    RPCResult::Type::NONE, "", "None"},
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"") +
                    HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CBlockHeader h;
    if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block header decode failed");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        if (!chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Must submit previous header (" + h.hashPrevBlock.GetHex() + ") first");
        }
    }

    BlockValidationState state;
    chainman.ProcessNewBlockHeaders({{h}}, /*min_pow_checked=*/true, state);
    if (state.IsValid()) return UniValue::VNULL;
    if (state.IsError()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    }
    throw JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason());
},
    };
}

void RegisterMiningRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &getnetworkhashps},
        {"mining", &getmininginfo},
        {"mining", &getdifficultyhealth},
        {"mining", &getmatmulchallenge},
        {"mining", &getmatmulchallengeprofile},
        {"mining", &getmatmulservicechallenge},
        {"mining", &getmatmulservicechallengeplan},
        {"mining", &getmatmulservicechallengeprofile},
        {"mining", &listmatmulservicechallengeprofiles},
        {"mining", &issuematmulservicechallengeprofile},
        {"mining", &solvematmulservicechallenge},
        {"mining", &verifymatmulserviceproof},
        {"mining", &redeemmatmulserviceproof},
        {"mining", &verifymatmulserviceproofs},
        {"mining", &redeemmatmulserviceproofs},
        {"mining", &prioritisetransaction},
        {"mining", &getprioritisedtransactions},
        {"mining", &getblocktemplate},
        {"mining", &submitblock},
        {"mining", &submitheader},

        {"hidden", &generatetoaddress},
        {"hidden", &generatetodescriptor},
        {"hidden", &generateblock},
        {"hidden", &generate},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
