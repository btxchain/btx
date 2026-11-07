// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/swarm_shardhold.h>

#include <modelnet/swarm_shardhold/keep.h>
#include <modelnet/swarm_shardhold/limits.h>
#include <modelnet/swarm_shardhold/request.h>

namespace modelnet {

bool SwarmShardHold::Request(const std::string& name, std::string& err)
{
    return SwarmShardHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmShardHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmShardHold::stored_name(const std::string& name) const
{
    return SwarmShardHoldKeep{}.first(m_book, name);
}

std::size_t SwarmShardHold::request_count() const
{
    return m_book.size();
}

bool SwarmShardHold::sharded() const
{
    if (m_book.sharded()) return true;
    return m_stay.sharded();
}

bool SwarmShardHold::running() const
{
    if (m_book.running()) return true;
    return m_stay.running();
}

int64_t SwarmShardHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmShardHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmShardHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmShardHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
