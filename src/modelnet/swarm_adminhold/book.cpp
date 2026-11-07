// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/book.h>

#include <utility>

namespace modelnet {

bool SwarmAdminHoldBook::contains(const std::string& channel) const
{
    if (channel.empty()) return false;
    return m_channels.find(channel) != m_channels.end();
}

int64_t SwarmAdminHoldBook::height_of(const std::string& channel) const
{
    const auto found = m_channels.find(channel);
    if (found == m_channels.end()) return 0;
    return found->second.refund_height;
}

std::vector<unsigned char> SwarmAdminHoldBook::key_of(const std::string& channel) const
{
    const auto found = m_channels.find(channel);
    if (found == m_channels.end()) return {};
    return found->second.sponsor_key;
}

std::size_t SwarmAdminHoldBook::size() const
{
    return m_channels.size();
}

bool SwarmAdminHoldBook::store(const std::string& channel,
                                int64_t refund_height,
                                const std::vector<unsigned char>& sponsor_key)
{
    if (contains(channel)) return false;
    SwarmAdminHoldRecord record = SwarmAdminHoldMakeRecord(channel, refund_height, sponsor_key);
    if (!SwarmAdminHoldRecordUsable(record)) return false;
    m_channels.emplace(channel, std::move(record));
    return true;
}

} // namespace modelnet
