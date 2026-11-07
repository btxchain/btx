// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/swarm_adminhold.h>

#include <modelnet/swarm_adminhold/moveheight.h>
#include <modelnet/swarm_adminhold/movekey.h>
#include <modelnet/swarm_adminhold/open.h>

namespace modelnet {

bool SwarmAdminHold::Open(const std::string& channel,
                           int64_t refund_height,
                           const std::vector<unsigned char>& sponsor_key,
                           std::string& err)
{
    return SwarmAdminHoldOpen{}.Apply(m_book, channel, refund_height, sponsor_key, err);
}

bool SwarmAdminHold::MoveHeight(const std::string& channel, int64_t next_height, std::string& err) const
{
    return SwarmAdminHoldMoveHeight{}.Apply(m_book, channel, next_height, err);
}

bool SwarmAdminHold::MoveKey(const std::string& channel,
                              const std::vector<unsigned char>& next_key,
                              std::string& err) const
{
    return SwarmAdminHoldMoveKey{}.Apply(m_book, channel, next_key, err);
}

bool SwarmAdminHold::opened(const std::string& channel) const
{
    return m_book.contains(channel);
}

int64_t SwarmAdminHold::refund_height(const std::string& channel) const
{
    return m_book.height_of(channel);
}

std::vector<unsigned char> SwarmAdminHold::sponsor_key(const std::string& channel) const
{
    return m_book.key_of(channel);
}

std::size_t SwarmAdminHold::channel_count() const
{
    return m_book.size();
}

bool SwarmAdminHold::broadcast() const
{
    return m_quiet.broadcast();
}

bool SwarmAdminHold::mined() const
{
    return m_quiet.mined();
}

int64_t SwarmAdminHold::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

std::string SwarmAdminHold::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
