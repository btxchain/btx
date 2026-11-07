// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_conflict.h>

namespace modelnet {

bool SwarmConflict::Offer(const std::string& task, const std::string& worker, const std::string& hash, std::string& err)
{
    if (task.empty() || worker.empty() || hash.empty()) {
        err = "TASK";
        return false;
    }
    const auto it = m_offers.find(task);
    if (it == m_offers.end()) {
        OfferRow row;
        row.worker = worker;
        row.hash = hash;
        m_offers.emplace(task, std::move(row));
        err.clear();
        return true;
    }
    if (it->second.hash != hash) {
        it->second.conflicted = true;
        err = "CONFLICT";
        return false;
    }
    err.clear();
    return true;
}

std::string SwarmConflict::Hash(const std::string& task) const
{
    const auto it = m_offers.find(task);
    if (it == m_offers.end()) {
        return std::string();
    }
    return it->second.hash;
}

bool SwarmConflict::conflicted(const std::string& task) const
{
    const auto it = m_offers.find(task);
    if (it == m_offers.end()) return false;
    return it->second.conflicted;
}

} // namespace modelnet
