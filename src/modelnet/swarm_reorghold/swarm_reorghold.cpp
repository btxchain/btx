// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/swarm_reorghold.h>

#include <modelnet/swarm_reorghold/exit.h>
#include <modelnet/swarm_reorghold/open.h>
#include <modelnet/swarm_reorghold/refund.h>
#include <modelnet/swarm_reorghold/reorg.h>

namespace modelnet {

bool SwarmReorgHold::Open(const std::string& channel, int64_t earned, std::string& err)
{
    return ReorgHoldOpen(m_book, channel, earned, err);
}

bool SwarmReorgHold::Reorg(std::string& err)
{
    return ReorgHoldReorg(m_book, err);
}

bool SwarmReorgHold::Exit(const std::string& channel, std::string& err)
{
    return ReorgHoldExit(m_book, channel, err);
}

bool SwarmReorgHold::Refund(const std::string& channel, std::string& err)
{
    return ReorgHoldRefund(m_book, channel, err);
}

int64_t SwarmReorgHold::earned() const
{
    return m_book.earned();
}

bool SwarmReorgHold::broadcast() const
{
    return m_silence.broadcast();
}

bool SwarmReorgHold::mined() const
{
    return m_silence.mined();
}

int64_t SwarmReorgHold::bytes_moved() const
{
    return m_silence.bytes_moved();
}

bool SwarmReorgHold::frozen() const
{
    return m_book.reorged();
}

bool SwarmReorgHold::has(const std::string& channel) const
{
    return m_book.contains(channel);
}

bool SwarmReorgHold::channel_frozen(const std::string& channel) const
{
    return m_book.channel_frozen(channel);
}

int64_t SwarmReorgHold::channel_earned(const std::string& channel) const
{
    return m_book.channel_earned(channel);
}

bool SwarmReorgHold::paid(const std::string& channel) const
{
    return m_book.paid(channel);
}

bool SwarmReorgHold::exited(const std::string& channel) const
{
    return m_book.exited(channel);
}

bool SwarmReorgHold::refund_built() const
{
    return m_book.refund_built();
}

std::size_t SwarmReorgHold::channels() const
{
    return m_book.size();
}

} // namespace modelnet
