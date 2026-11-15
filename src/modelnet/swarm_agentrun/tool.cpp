// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/tool.h>

#include <modelnet/swarm_agentrun/codes.h>
#include <modelnet/swarm_agentrun/trace.h>

#include <cstddef>
#include <set>
#include <string>

namespace modelnet {

bool SwarmAgentRunTools::Reuse(const std::string& digest, bool is_private, SwarmAgentRunTrace& trace, std::string& err)
{
    if (digest.empty()) {
        err = kAgentRunTool;
        return false;
    }
    if (is_private) {
        err = kAgentRunPrivateData;
        return false;
    }
    if (m_digests.find(digest) != m_digests.end()) {
        err = kAgentRunReplay;
        return false;
    }
    m_digests.insert(digest);
    trace.Append(kAgentRunEvTool);
    err.clear();
    return true;
}

bool SwarmAgentRunTools::contains(const std::string& digest) const
{
    return m_digests.find(digest) != m_digests.end();
}

std::size_t SwarmAgentRunTools::count() const
{
    return m_digests.size();
}

} // namespace modelnet
