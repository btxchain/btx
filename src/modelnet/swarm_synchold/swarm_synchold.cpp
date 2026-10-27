// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/swarm_synchold.h>

#include <modelnet/swarm_synchold/keep.h>
#include <modelnet/swarm_synchold/limits.h>
#include <modelnet/swarm_synchold/request.h>

namespace modelnet {

bool SwarmSyncHold::Request(const std::string& name, std::string& err)
{
    return SwarmSyncHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmSyncHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmSyncHold::stored_name(const std::string& name) const
{
    return SwarmSyncHoldKeep{}.first(m_book, name);
}

std::size_t SwarmSyncHold::request_count() const
{
    return m_book.size();
}

bool SwarmSyncHold::synced() const
{
    if (m_book.synced()) return true;
    return m_stay.synced();
}

int64_t SwarmSyncHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmSyncHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmSyncHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmSyncHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
