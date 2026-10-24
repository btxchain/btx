// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/report.h>

#include <set>

namespace modelnet {

void SwarmEvaluationReportBook::add(const SwarmEvaluationReport& report)
{
    SwarmEvaluationReport row = report;
    row.accepting = true;
    m_rows.push_back(row);
}

std::size_t SwarmEvaluationReportBook::count_for(const std::string& candidate) const
{
    std::size_t count = 0;
    for (const SwarmEvaluationReport& row : m_rows) {
        if (row.candidate == candidate && row.accepting) {
            ++count;
        }
    }
    return count;
}

std::size_t SwarmEvaluationReportBook::distinct_evaluators(const std::string& candidate) const
{
    std::set<std::string> evaluators;
    for (const SwarmEvaluationReport& row : m_rows) {
        if (row.candidate == candidate && row.accepting) {
            evaluators.insert(row.evaluator);
        }
    }
    return evaluators.size();
}

std::size_t SwarmEvaluationReportBook::distinct_domains(const std::string& candidate) const
{
    std::set<std::string> domains;
    for (const SwarmEvaluationReport& row : m_rows) {
        if (row.candidate == candidate && row.accepting) {
            domains.insert(row.evaluator_domain);
        }
    }
    return domains.size();
}

} // namespace modelnet
