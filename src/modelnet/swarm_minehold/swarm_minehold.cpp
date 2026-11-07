// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/swarm_minehold.h>

#include <modelnet/swarm_minehold/keep.h>
#include <modelnet/swarm_minehold/limits.h>
#include <modelnet/swarm_minehold/request.h>

namespace modelnet {

bool SwarmMineHold::Request(const std::string& name, std::string& err)
{
    return SwarmMineHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmMineHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmMineHold::stored_name(const std::string& name) const
{
    return SwarmMineHoldKeep{}.first(m_book, name);
}

std::size_t SwarmMineHold::request_count() const
{
    return m_book.size();
}

bool SwarmMineHold::mined() const
{
    if (m_book.mined()) return true;
    if (m_mine.mined()) return true;
    return m_stay.mined();
}

int64_t SwarmMineHold::blocks() const
{
    if (m_book.blocks() != kSwarmMineHoldBlocks) return m_book.blocks();
    if (m_mine.blocks() != kSwarmMineHoldBlocks) return m_mine.blocks();
    return m_stay.blocks();
}

int64_t SwarmMineHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmMineHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmMineHold::broadcast() const
{
    if (m_book.broadcast()) return true;
    return m_quiet.broadcast();
}

bool SwarmMineHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

} // namespace modelnet
