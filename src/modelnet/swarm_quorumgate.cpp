// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quorumgate.h>

#include <set>

namespace modelnet {

bool SwarmQuorumGate::Submit(const std::string& report, const std::string& author, const std::string& domain, std::string& err)
{
    if (report.empty() || author.empty() || domain.empty()) {
        err = "REPORT";
        return false;
    }
    if (m_reports.find(report) != m_reports.end()) {
        err = "REPLAY";
        return false;
    }
    ReportRow row;
    row.author = author;
    row.domain = domain;
    m_reports.emplace(report, std::move(row));
    err.clear();
    return true;
}

bool SwarmQuorumGate::Open(std::string& err)
{
    std::set<std::string> authors;
    std::set<std::string> domains;
    for (const auto& item : m_reports) {
        authors.insert(item.second.author);
        domains.insert(item.second.domain);
    }
    if (authors.size() < 2 || domains.size() < 2) {
        err = "QUORUM";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
