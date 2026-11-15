// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_resultcache.h>

#include <string>

namespace modelnet {

bool SwarmResultCache::Put(const std::string& key, const std::string& hash, std::string& err)
{
    if (key.empty() || hash.empty()) {
        err = "CACHE";
        return false;
    }
    const auto it = m_entries.find(key);
    if (it == m_entries.end()) {
        m_entries.emplace(key, hash);
        err.clear();
        return true;
    }
    if (it->second == hash) {
        err.clear();
        return true;
    }
    err = "CONFLICT";
    return false;
}

std::string SwarmResultCache::Get(const std::string& key) const
{
    const auto it = m_entries.find(key);
    if (it == m_entries.end()) {
        return std::string();
    }
    return it->second;
}

} // namespace modelnet
