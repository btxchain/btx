// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/channel.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

const std::string& SwarmGenerationChannels::staged(const std::string& channel) const
{
    const auto it = m_heads.find(channel);
    if (it == m_heads.end()) return m_blank;
    return it->second.staged;
}

const std::string& SwarmGenerationChannels::active(const std::string& channel) const
{
    const auto it = m_heads.find(channel);
    if (it == m_heads.end()) return m_blank;
    return it->second.active;
}

bool SwarmGenerationChannels::has_staged(const std::string& channel) const
{
    const auto it = m_heads.find(channel);
    return it != m_heads.end() && !it->second.staged.empty();
}

void SwarmGenerationChannels::note_policy(const std::string& channel, const std::string& policy)
{
    m_heads[channel].policy = policy;
}

void SwarmGenerationChannels::stage_follow(const std::string& channel, const std::string& candidate_id)
{
    Head& head = m_heads[channel];
    head.staged = candidate_id;
    head.policy = kSwarmGenerationFollow;
}

bool SwarmGenerationChannels::adopt(const std::string& channel, std::string& previous, std::string& adopted)
{
    const auto it = m_heads.find(channel);
    if (it == m_heads.end() || it->second.staged.empty()) return false;
    previous = it->second.active;
    adopted = it->second.staged;
    it->second.active = it->second.staged;
    it->second.staged.clear();
    return true;
}

std::vector<std::pair<std::string, std::string>> SwarmGenerationChannels::actives() const
{
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(m_heads.size());
    for (const auto& item : m_heads) {
        out.emplace_back(item.first, item.second.active);
    }
    return out;
}

} // namespace modelnet
