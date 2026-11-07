// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalboard/ledger.h>

#include <modelnet/swarm_evalboard/codes.h>

namespace modelnet {

bool SwarmEvalLedger::Store(const SwarmEvalReport& report, std::string& err)
{
    std::vector<SwarmEvalReport>& rows = m_rows[report.subject];
    for (const SwarmEvalReport& row : rows) {
        if (row.author == report.author) {
            err = kSwarmEvalReplay;
            return false;
        }
    }
    rows.push_back(report);
    err.clear();
    return true;
}

std::vector<SwarmEvalReport> SwarmEvalLedger::scores(const std::string& subject) const
{
    const auto found = m_rows.find(subject);
    if (found == m_rows.end()) return {};
    return found->second;
}

} // namespace modelnet
