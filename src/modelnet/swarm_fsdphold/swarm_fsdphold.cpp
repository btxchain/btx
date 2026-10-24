// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/swarm_fsdphold.h>

#include <modelnet/swarm_fsdphold/keep.h>
#include <modelnet/swarm_fsdphold/limits.h>
#include <modelnet/swarm_fsdphold/request.h>

namespace modelnet {

bool SwarmFsdpHold::Request(const std::string& name, std::string& err)
{
    return SwarmFsdpHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmFsdpHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmFsdpHold::stored_name(const std::string& name) const
{
    return SwarmFsdpHoldKeep{}.first(m_book, name);
}

std::size_t SwarmFsdpHold::request_count() const
{
    return m_book.size();
}

bool SwarmFsdpHold::running() const
{
    if (m_book.running()) return true;
    return m_stay.running();
}

int64_t SwarmFsdpHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmFsdpHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmFsdpHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmFsdpHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
