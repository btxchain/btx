// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_speculate.h>

#include <string>

namespace modelnet {

bool SwarmSpeculate::Open(const std::string& primary, const std::string& branch, std::string& err)
{
    if (primary.empty() || branch.empty()) {
        err = "TASK";
        return false;
    }
    if (m_branches.find(branch) != m_branches.end()) {
        err = "REPLAY";
        return false;
    }
    Branch stored;
    stored.primary = primary;
    m_branches.emplace(branch, stored);
    err.clear();
    return true;
}

bool SwarmSpeculate::Finish(const std::string& branch, const std::string& result_hash, std::string& err)
{
    auto it = m_branches.find(branch);
    if (it == m_branches.end()) {
        err = "TASK";
        return false;
    }
    if (result_hash.empty()) {
        err = "HASH";
        return false;
    }
    Branch& stored = it->second;
    if (!stored.finished) {
        stored.result_hash = result_hash;
        stored.finished = true;
        err.clear();
        return true;
    }
    if (stored.result_hash == result_hash) {
        err.clear();
        return true;
    }
    err = "CONFLICT";
    return false;
}

bool SwarmSpeculate::Reuse(const std::string& primary, const std::string& primary_hash, std::string& reused_branch, std::string& err)
{
    reused_branch.clear();
    for (const auto& item : m_branches) {
        const Branch& stored = item.second;
        if (stored.primary != primary || !stored.finished) continue;
        if (stored.result_hash != primary_hash) continue;
        reused_branch = item.first;
        err.clear();
        return true;
    }
    err = "NO_REUSE";
    return false;
}

} // namespace modelnet
