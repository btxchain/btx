// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/book.h>

#include <modelnet/swarm_launchprof/limits.h>

#include <utility>

namespace modelnet {

bool SwarmLaunchProfileBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_names.find(name) != m_names.end();
}

std::string SwarmLaunchProfileBook::name_of(const std::string& name) const
{
    const auto found = m_names.find(name);
    if (found == m_names.end()) return {};
    return found->second.name();
}

std::size_t SwarmLaunchProfileBook::size() const
{
    return m_names.size();
}

bool SwarmLaunchProfileBook::renamed() const
{
    for (const auto& entry : m_names) {
        if (entry.second.renamed()) return true;
    }
    return kSwarmLaunchProfileRenamed;
}

int64_t SwarmLaunchProfileBook::bytes_moved() const
{
    int64_t total = kSwarmLaunchProfileBytesMoved;
    for (const auto& entry : m_names) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmLaunchProfileBook::gpu() const
{
    for (const auto& entry : m_names) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmLaunchProfileGpu;
}

bool SwarmLaunchProfileBook::launched() const
{
    for (const auto& entry : m_names) {
        if (entry.second.launched()) return true;
    }
    return kSwarmLaunchProfileLaunched;
}

bool SwarmLaunchProfileBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmLaunchProfileRecord record = SwarmLaunchProfileRecord::Make(name);
    if (!SwarmLaunchProfileRecordUsable(record)) return false;
    m_names.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
