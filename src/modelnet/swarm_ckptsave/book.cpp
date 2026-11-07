// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/book.h>

#include <modelnet/swarm_ckptsave/limits.h>

#include <utility>

namespace modelnet {

bool SwarmCkptSaveBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmCkptSaveBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmCkptSaveBook::size() const
{
    return m_requests.size();
}

bool SwarmCkptSaveBook::saved() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.saved()) return true;
    }
    return kSwarmCkptSaveSaved;
}

int64_t SwarmCkptSaveBook::bytes_moved() const
{
    int64_t total = kSwarmCkptSaveBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmCkptSaveBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmCkptSaveGpu;
}

bool SwarmCkptSaveBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmCkptSaveLaunched;
}

bool SwarmCkptSaveBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmCkptSaveRecord record = SwarmCkptSaveRecord::Make(name);
    if (!SwarmCkptSaveRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
