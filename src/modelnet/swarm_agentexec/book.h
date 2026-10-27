// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_BOOK_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_BOOK_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Prefixes stored by a successful Allow.
 * Add refuses an empty prefix and a prefix already present.
 * A refused Add leaves the stored prefixes unchanged.
 * Allows is true when path begins with any stored prefix.
 * Paths stay opaque strings. There is no erase.
 */
class SwarmAgentExecBook {
public:
    bool Contains(const std::string& prefix) const;
    bool Add(const std::string& prefix);
    bool Allows(const std::string& path) const;

private:
    std::vector<std::string> m_prefixes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_BOOK_H
