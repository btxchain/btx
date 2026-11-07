// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rotgate.h>

#include <set>

namespace modelnet {

bool SwarmRotGate::Record(const std::string& report, const std::string& holdout, bool rotating, std::string& err)
{
    if (report.empty() || holdout.empty()) {
        err = "REPORT";
        return false;
    }
    if (m_stored.find(report) != m_stored.end()) {
        err = "REPLAY";
        return false;
    }
    if (!rotating) {
        err = "NOT_ROTATING";
        return false;
    }
    m_stored.emplace(report, holdout);
    err.clear();
    return true;
}

bool SwarmRotGate::rotated() const
{
    std::set<std::string> holdouts;
    for (const auto& stored : m_stored) {
        holdouts.insert(stored.second);
    }
    return holdouts.size() >= 2;
}

int SwarmRotGate::accepted() const
{
    return static_cast<int>(m_stored.size());
}

} // namespace modelnet
