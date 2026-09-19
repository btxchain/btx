// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_QUERY_ROUTER_H
#define BITCOIN_MODELNET_QUERY_ROUTER_H

#include <modelnet/metadata_gossip.h>
#include <modelnet/search.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Hard cap on IDs placed in a query summary. Never dump the catalog. */
constexpr size_t QUERY_SAMPLE_MAX = 32;
/** Spec E.1: one query's active remote tasks. */
constexpr int QUERY_PROBE_MAX = 8;
/** Spec E.1: one query's cumulative remote tasks. */
constexpr int QUERY_CUMULATIVE_TASKS_MAX = 32;
constexpr int QUERY_USEFUL_TARGET_DEFAULT = 25;
constexpr int64_t QUERY_DEADLINE_MS = 8000;

struct QueryBudget {
    int max_active_remote{QUERY_PROBE_MAX};
    int max_cumulative_remote{QUERY_CUMULATIVE_TASKS_MAX};
    int useful_target{QUERY_USEFUL_TARGET_DEFAULT};
    size_t max_sample{QUERY_SAMPLE_MAX};
    int64_t deadline_ms{QUERY_DEADLINE_MS};
};

struct QueryPeerHint {
    std::string endpoint;
    std::string netgroup;
    bool summary_likely{false};
    bool summary_unknown{true};
    bool saturated{false};
    /** Local observation only. Must not rank peers or results. */
    double throughput_bps{0};
};

struct DynamicQueryPlan {
    bool local_only{false};
    std::vector<std::string> probe_peers;
    std::vector<std::string> exploration_peers;
    int remaining_tasks{0};
    bool expand{false};
    /** True when every peer claimed a match and the probe was still capped. */
    bool all_match_capped{false};
};

struct RoutedQuery {
    QuerySummary summary;
    GossipDigest digest;
    SearchCoverage coverage;
    bool truncated{false};
    bool complete{false};
};

/**
 * Dynamic query planner over the existing SearchIndex.
 * Summaries only; does not retarget the catalog onto object storage.
 */
class QueryRouter {
    SearchIndex* m_idx{nullptr};
    QueryBudget m_budget;
    QueryDedupe m_dedupe;
    int m_remote_tasks{0};
    bool m_cancelled{false};
    mutable uint64_t m_snapshot_generation{1};

public:
    explicit QueryRouter(QueryBudget budget = {});
    void Bind(SearchIndex* idx) { m_idx = idx; }

    size_t SampleCap() const;
    QuerySummary SummarizeIds(const std::vector<std::string>& ids) const;
    QuerySummary SummarizeHits(const std::vector<SearchHit>& hits) const;
    RoutedQuery ExecuteLocal(const SearchQuery& q, int64_t now_ms) const;
    DynamicQueryPlan Plan(const SearchQuery& q, const std::vector<QueryPeerHint>& peers,
                          int unique_useful) const;

    bool AdmitQuery(const std::string& query_id);
    bool ShouldForward(int ttl, int hop) const;
    void Cancel();
    bool Cancelled() const { return m_cancelled; }
    int RemoteTasks() const { return m_remote_tasks; }
    void NoteRemoteTasks(int n);
};

/** Throughput is not ranking or monetary authority. Always false. */
bool ProviderThroughputIsRankingAuthority();
/** Preference ignores throughput_bps. Lower sorts earlier among comparable hops. */
int QueryPeerPreference(const QueryPeerHint& p);
std::vector<std::string> HitIds(const std::vector<SearchHit>& hits);

} // namespace modelnet

#endif // BITCOIN_MODELNET_QUERY_ROUTER_H
