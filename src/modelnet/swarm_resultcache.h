// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RESULTCACHE_H
#define BTX_MODELNET_SWARM_RESULTCACHE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Local map from a result key to the first content hash stored for it.
 * A repeated put of that same hash succeeds. A different hash is left
 * stored and reported as CONFLICT. An empty key or hash stores nothing.
 */
class SwarmResultCache {
public:
    bool Put(const std::string& key, const std::string& hash, std::string& err);
    std::string Get(const std::string& key) const;

private:
    std::map<std::string, std::string> m_entries;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RESULTCACHE_H
