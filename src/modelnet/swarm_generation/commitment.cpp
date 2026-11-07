// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/commitment.h>

#include <modelnet/swarm_generation/limits.h>

#include <set>
#include <utility>

namespace modelnet {

void SwarmGenerationCommitment::add(SwarmGenerationReport report)
{
    m_reports.push_back(std::move(report));
}

std::size_t SwarmGenerationCommitment::count(const std::string& candidate_id) const
{
    std::size_t n = 0;
    for (const SwarmGenerationReport& row : m_reports) {
        if (row.candidate_id == candidate_id) ++n;
    }
    return n;
}

bool SwarmGenerationCommitment::qualified(const std::string& candidate_id) const
{
    std::set<std::string> evaluators;
    std::set<std::string> domains;
    std::size_t n = 0;
    for (const SwarmGenerationReport& row : m_reports) {
        if (row.candidate_id != candidate_id) continue;
        if (row.author_sees_holdout) return false;
        if (row.safety_regression) return false;
        if (row.broad_regression) return false;
        evaluators.insert(row.evaluator);
        domains.insert(row.evaluator_domain);
        ++n;
    }
    if (n < static_cast<std::size_t>(kSwarmGenerationQuorumReports)) return false;
    return evaluators.size() >= static_cast<std::size_t>(kSwarmGenerationQuorumReports) &&
           domains.size() >= static_cast<std::size_t>(kSwarmGenerationQuorumReports);
}

} // namespace modelnet
