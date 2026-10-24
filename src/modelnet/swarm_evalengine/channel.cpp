// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/channel.h>

#include <modelnet/swarm_evalengine/codes.h>

namespace modelnet {

std::string SwarmEvaluationChannelBook::staged(const std::string& channel) const
{
    const auto it = m_rows.find(channel);
    if (it == m_rows.end()) {
        return std::string{};
    }
    return it->second.staged;
}

std::string SwarmEvaluationChannelBook::active(const std::string& channel) const
{
    const auto it = m_rows.find(channel);
    if (it == m_rows.end()) {
        return std::string{};
    }
    return it->second.active;
}

bool SwarmEvaluationChannelBook::has_staged(const std::string& channel) const
{
    return !staged(channel).empty();
}

void SwarmEvaluationChannelBook::set_staged(const std::string& channel, const std::string& candidate)
{
    SwarmEvaluationChannel& head = m_rows[channel];
    head.channel = channel;
    head.staged = candidate;
    head.policy = kSwarmEvaluationPolicyFollow;
}

void SwarmEvaluationChannelBook::set_policy(const std::string& channel, const std::string& policy)
{
    SwarmEvaluationChannel& head = m_rows[channel];
    head.channel = channel;
    head.policy = policy;
}

bool SwarmEvaluationChannelBook::adopt_staged(const std::string& channel, std::string& previous, std::string& adopted)
{
    auto it = m_rows.find(channel);
    if (it == m_rows.end() || it->second.staged.empty()) {
        return false;
    }
    previous = it->second.active;
    adopted = it->second.staged;
    it->second.active = adopted;
    it->second.staged.clear();
    return true;
}

} // namespace modelnet
