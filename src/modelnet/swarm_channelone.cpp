// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelone.h>

namespace modelnet {

bool SwarmChannelOne::Open(const std::string& channel, int64_t capacity, std::string& err)
{
    if (channel.empty()) {
        err = "CHANNEL";
        return false;
    }
    if (capacity < 1) {
        err = "CAPACITY";
        return false;
    }
    if (!m_channel.empty()) {
        err = "NOT_OPENED";
        return false;
    }
    m_channel = channel;
    m_capacity = capacity;
    err.clear();
    return true;
}

const std::string& SwarmChannelOne::open_channel() const
{
    return m_channel;
}

int64_t SwarmChannelOne::capacity() const
{
    return m_capacity;
}

} // namespace modelnet
