// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/channel.h>

#include <modelnet/swarm_forward/codes.h>

namespace modelnet {

bool SwarmForwardChannel::Open(const std::string& channel, int64_t liquidity, std::string& err)
{
    if (!m_open.Accept(channel, liquidity, err)) {
        return false;
    }
    if (m_remaining.find(channel) != m_remaining.end()) {
        err = kSwarmForwardReplay;
        return false;
    }
    m_remaining.emplace(channel, liquidity);
    err.clear();
    return true;
}

bool SwarmForwardChannel::Known(const std::string& channel) const
{
    return m_remaining.find(channel) != m_remaining.end();
}

int64_t SwarmForwardChannel::Remaining(const std::string& channel) const
{
    const auto it = m_remaining.find(channel);
    if (it == m_remaining.end()) return 0;
    return it->second;
}

bool SwarmForwardChannel::Debit(const std::string& channel, int64_t amount)
{
    const auto it = m_remaining.find(channel);
    if (it == m_remaining.end() || amount < 1 || amount > it->second) {
        return false;
    }
    it->second -= amount;
    return true;
}

} // namespace modelnet
