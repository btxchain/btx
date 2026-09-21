// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/query_router.h>

#include <algorithm>
#include <set>

namespace modelnet {

namespace {

int ClampActive(const QueryBudget& b)
{
    int n = b.max_active_remote;
    if (n <= 0) n = QUERY_PROBE_MAX;
    if (n > QUERY_PROBE_MAX) n = QUERY_PROBE_MAX;
    return n;
}

std::vector<std::string> PickDiverse(const std::vector<QueryPeerHint>& src, int n)
{
    std::vector<std::string> out;
    if (n <= 0) return out;
    std::set<std::string> ngs;
    std::set<std::string> used;
    for (const auto& p : src) {
        if (static_cast<int>(out.size()) >= n) break;
        if (p.endpoint.empty() || used.count(p.endpoint)) continue;
        const std::string ng = p.netgroup.empty() ? p.endpoint : p.netgroup;
        if (ngs.count(ng)) continue;
        ngs.insert(ng);
        used.insert(p.endpoint);
        out.push_back(p.endpoint);
    }
    for (const auto& p : src) {
        if (static_cast<int>(out.size()) >= n) break;
        if (p.endpoint.empty() || used.count(p.endpoint)) continue;
        used.insert(p.endpoint);
        out.push_back(p.endpoint);
    }
    return out;
}

} // namespace

QueryRouter::QueryRouter(QueryBudget budget) : m_budget(budget) {}

size_t QueryRouter::SampleCap() const
{
    size_t cap = m_budget.max_sample == 0 ? QUERY_SAMPLE_MAX : m_budget.max_sample;
    if (cap > QUERY_SAMPLE_MAX) cap = QUERY_SAMPLE_MAX;
    return cap;
}

QuerySummary QueryRouter::SummarizeIds(const std::vector<std::string>& ids) const
{
    QuerySummary s = SummarizeQueryHits(ids, SampleCap());
    s.snapshot_generation = m_snapshot_generation++;
    return s;
}

QuerySummary QueryRouter::SummarizeHits(const std::vector<SearchHit>& hits) const
{
    return SummarizeIds(HitIds(hits));
}

RoutedQuery QueryRouter::ExecuteLocal(const SearchQuery& q, int64_t now_ms) const
{
    RoutedQuery out;
    out.coverage.local = true;
    out.coverage.complete = false;
    if (!m_idx) return out;

    SearchQuery qq = q;
    if (qq.limit <= 0) qq.limit = 50;
    if (qq.limit > static_cast<int>(SEARCH_PAGE_MAX)) qq.limit = static_cast<int>(SEARCH_PAGE_MAX);

    const auto hits = m_idx->Search(qq, now_ms);
    const auto ids = HitIds(hits);
    out.summary = SummarizeIds(ids);
    auto digest_ids = ids;
    std::sort(digest_ids.begin(), digest_ids.end());
    out.digest.catalog_digest_hex = CatalogDigestHex(digest_ids);
    out.digest.entry_count = static_cast<uint32_t>(ids.size());
    out.truncated = out.summary.truncated > 0 ||
                    static_cast<int>(hits.size()) >= qq.limit;
    out.complete = q.scope == SearchScope::LOCAL && !out.truncated;
    out.coverage.complete = out.complete;
    return out;
}

DynamicQueryPlan QueryRouter::Plan(const SearchQuery& q, const std::vector<QueryPeerHint>& peers,
                                   int unique_useful) const
{
    DynamicQueryPlan plan;
    const int cumulative_cap = m_budget.max_cumulative_remote > 0 ? m_budget.max_cumulative_remote
                                                                  : QUERY_CUMULATIVE_TASKS_MAX;
    plan.remaining_tasks = std::max(0, cumulative_cap - m_remote_tasks);
    if (m_cancelled || q.scope == SearchScope::LOCAL) {
        plan.local_only = true;
        return plan;
    }

    const int useful_target = m_budget.useful_target > 0 ? m_budget.useful_target
                                                         : QUERY_USEFUL_TARGET_DEFAULT;
    if (unique_useful >= useful_target) {
        plan.expand = false;
        return plan;
    }

    const int active = std::min(ClampActive(m_budget), plan.remaining_tasks);
    if (active <= 0) return plan;
    plan.expand = true;

    std::vector<QueryPeerHint> likely;
    std::vector<QueryPeerHint> unknown;
    likely.reserve(peers.size());
    unknown.reserve(peers.size());
    int claimed = 0;
    int usable = 0;
    for (const auto& p : peers) {
        if (p.endpoint.empty()) continue;
        ++usable;
        // throughput_bps is intentionally unused.
        (void)p.throughput_bps;
        if (p.saturated || p.summary_unknown || !p.summary_likely) {
            unknown.push_back(p);
        } else {
            likely.push_back(p);
            ++claimed;
        }
    }
    if (claimed > 0 && claimed == usable && usable > active) {
        plan.all_match_capped = true;
    }

    int explore_slots = 0;
    if (!unknown.empty()) {
        if (likely.empty()) explore_slots = std::min(active, static_cast<int>(unknown.size()));
        else if (active >= 2) explore_slots = 1;
    }
    const int likely_slots = std::max(0, active - explore_slots);
    plan.probe_peers = PickDiverse(likely, likely_slots);
    plan.exploration_peers = PickDiverse(unknown, explore_slots);

    std::set<std::string> taken(plan.probe_peers.begin(), plan.probe_peers.end());
    for (const auto& e : plan.exploration_peers) taken.insert(e);
    const int need = active - static_cast<int>(taken.size());
    if (need > 0) {
        std::vector<QueryPeerHint> rest;
        for (const auto& p : unknown) {
            if (!taken.count(p.endpoint)) rest.push_back(p);
        }
        for (const auto& p : likely) {
            if (!taken.count(p.endpoint)) rest.push_back(p);
        }
        const auto extra = PickDiverse(rest, need);
        plan.exploration_peers.insert(plan.exploration_peers.end(), extra.begin(), extra.end());
    }
    return plan;
}

bool QueryRouter::AdmitQuery(const std::string& query_id)
{
    return m_dedupe.Admit(query_id);
}

bool QueryRouter::ShouldForward(int ttl, int hop) const
{
    if (m_cancelled) return false;
    return ShouldForwardSearch(ttl, hop);
}

void QueryRouter::Cancel()
{
    m_cancelled = true;
}

void QueryRouter::NoteRemoteTasks(int n)
{
    if (n > 0) m_remote_tasks += n;
}

bool ProviderThroughputIsRankingAuthority()
{
    return false;
}

int QueryPeerPreference(const QueryPeerHint& p)
{
    (void)p.throughput_bps;
    if (p.saturated) return 2;
    if (p.summary_unknown || !p.summary_likely) return 1;
    return 0;
}

std::vector<std::string> HitIds(const std::vector<SearchHit>& hits)
{
    std::vector<std::string> ids;
    ids.reserve(hits.size());
    for (const auto& h : hits) ids.push_back(h.rec.model_id.Hex());
    return ids;
}

} // namespace modelnet
