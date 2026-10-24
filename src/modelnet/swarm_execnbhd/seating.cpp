// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/seating.h>

#include <modelnet/swarm_execnbhd/codes.h>
#include <modelnet/swarm_execnbhd/nearby.h>
#include <modelnet/swarm_execnbhd/remote.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmExecNbhdSeating::Replace(const std::vector<SwarmExecNbhdRecord>& eligible, std::string& err)
{
    const std::vector<SwarmExecNbhdRecord> nearby = SwarmExecNbhdSelectNearby(eligible);
    const std::vector<SwarmExecNbhdRecord> remote = SwarmExecNbhdSelectRemote(eligible, nearby);

    std::map<std::string, SwarmExecNbhdRecord> next_nearby;
    std::map<std::string, SwarmExecNbhdRecord> next_remote;
    for (const SwarmExecNbhdRecord& row : nearby) {
        next_nearby.emplace(row.peer, row);
    }
    for (const SwarmExecNbhdRecord& row : remote) {
        next_remote.emplace(row.peer, row);
    }
    m_nearby.swap(next_nearby);
    m_remote.swap(next_remote);
    return SwarmExecNbhdAccept(err);
}

int64_t SwarmExecNbhdSeating::nearby_count() const
{
    return static_cast<int64_t>(m_nearby.size());
}

int64_t SwarmExecNbhdSeating::remote_count() const
{
    return static_cast<int64_t>(m_remote.size());
}

bool SwarmExecNbhdSeating::nearby(const std::string& peer) const
{
    return m_nearby.find(peer) != m_nearby.end();
}

bool SwarmExecNbhdSeating::remote(const std::string& peer) const
{
    return m_remote.find(peer) != m_remote.end();
}

bool SwarmExecNbhdSeating::seated(const std::string& peer) const
{
    return nearby(peer) || remote(peer);
}

const SwarmExecNbhdRecord* SwarmExecNbhdSeating::Find(const std::string& peer) const
{
    const auto near = m_nearby.find(peer);
    if (near != m_nearby.end()) {
        return &near->second;
    }
    const auto far = m_remote.find(peer);
    if (far != m_remote.end()) {
        return &far->second;
    }
    return nullptr;
}

std::string SwarmExecNbhdSeating::domain(const std::string& peer) const
{
    const SwarmExecNbhdRecord* row = Find(peer);
    if (row == nullptr) {
        return {};
    }
    return row->trust_domain;
}

} // namespace modelnet
