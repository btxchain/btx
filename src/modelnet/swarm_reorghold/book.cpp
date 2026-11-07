// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/book.h>

#include <modelnet/swarm_reorghold/atoms.h>

namespace modelnet {

bool ReorgHoldBook::reorged() const
{
    return m_reorged;
}

bool ReorgHoldBook::contains(const std::string& channel) const
{
    return m_channels.find(channel) != m_channels.end();
}

bool ReorgHoldBook::channel_frozen(const std::string& channel) const
{
    const auto found = m_channels.find(channel);
    if (found == m_channels.end()) return false;
    return found->second.frozen;
}

int64_t ReorgHoldBook::channel_earned(const std::string& channel) const
{
    const auto found = m_channels.find(channel);
    if (found == m_channels.end()) return 0;
    return found->second.earned;
}

bool ReorgHoldBook::paid(const std::string& channel) const
{
    const auto found = m_channels.find(channel);
    if (found == m_channels.end()) return false;
    return ReorgHoldChannelPaid(found->second);
}

bool ReorgHoldBook::exited(const std::string& channel) const
{
    const auto found = m_channels.find(channel);
    if (found == m_channels.end()) return false;
    return ReorgHoldChannelExited(found->second);
}

bool ReorgHoldBook::refund_built() const
{
    return false;
}

int64_t ReorgHoldBook::earned() const
{
    return m_earned;
}

std::size_t ReorgHoldBook::size() const
{
    return m_channels.size();
}

bool ReorgHoldBook::Sum(int64_t& total) const
{
    total = 0;
    for (const auto& item : m_channels) {
        int64_t next = 0;
        if (!ReorgHoldAddAtoms(total, item.second.earned, next)) return false;
        total = next;
    }
    return true;
}

bool ReorgHoldBook::Insert(const std::string& channel, int64_t earned)
{
    if (m_reorged || channel.empty() || earned < 0) return false;
    if (m_channels.find(channel) != m_channels.end()) return false;
    int64_t next = 0;
    if (!ReorgHoldAddAtoms(m_earned, earned, next)) return false;
    const auto inserted = m_channels.emplace(channel, ReorgHoldMakeChannel(channel, earned));
    if (!inserted.second) return false;
    m_earned = next;
    return true;
}

void ReorgHoldBook::FreezeAll()
{
    for (auto& item : m_channels) {
        ReorgHoldFreezeChannel(item.second);
    }
    m_reorged = true;
}

bool ReorgHoldBook::AcceptEarned(int64_t earned_atoms)
{
    if (earned_atoms != m_earned) return false;
    m_earned = earned_atoms;
    return true;
}

} // namespace modelnet
