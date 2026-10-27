// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_TOOL_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_TOOL_H

#include <cstddef>
#include <set>
#include <string>

namespace modelnet {

class SwarmAgentRunTrace;

/**
 * Public tool digests stored once.
 * An empty digest is TOOL. A private digest is PRIVATE_DATA and stores
 * nothing, including when that digest was already stored as public.
 * A second store of the same public digest is REPLAY. Lookup of a stored
 * public digest returns true. A digest that was never stored returns false.
 */
class SwarmAgentRunTools {
public:
    bool Reuse(const std::string& digest, bool is_private, SwarmAgentRunTrace& trace, std::string& err);
    bool contains(const std::string& digest) const;
    std::size_t count() const;

private:
    std::set<std::string> m_digests;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_TOOL_H
