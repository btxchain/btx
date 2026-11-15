// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_SHARED_H
#define BTX_MODELNET_SWARM_AGENTS_SHARED_H

#include <map>
#include <set>
#include <string>
#include <utility>

namespace modelnet {

/**
 * First published hash for a key wins.
 * A later different hash is CONFLICT and does not replace the first.
 * The same hash publishes again. An empty key or hash is HASH and
 * stores nothing.
 * Attach records a consumer only when that consumer presents the
 * stored hash. A different hash is CONFLICT and the consumer is not
 * recorded. An empty consumer is CONSUMER.
 */
class SwarmAgentSharedResult {
public:
    bool Publish(const std::string& key, const std::string& hash, std::string& err);
    bool Attach(const std::string& consumer, const std::string& key, const std::string& hash, std::string& err);
    std::string Shared(const std::string& key) const;
    bool attached(const std::string& consumer, const std::string& key) const;

private:
    std::map<std::string, std::string> m_hash;
    std::set<std::pair<std::string, std::string>> m_consumers;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_SHARED_H
