// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/journal.h>

#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmAgentExecJournal::Seen(const std::string& path, const std::string& payload) const
{
    const std::pair<std::string, std::string> key{path, payload};
    return m_runs.find(key) != m_runs.end();
}

bool SwarmAgentExecJournal::Put(const std::string& path, const std::string& payload, const std::string& digest)
{
    const std::pair<std::string, std::string> key{path, payload};
    const auto [it, inserted] = m_runs.emplace(key, digest);
    (void)it;
    return inserted;
}

} // namespace modelnet
