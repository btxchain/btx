// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/swarm_ablatehold.h>

#include <modelnet/swarm_ablatehold/keep.h>
#include <modelnet/swarm_ablatehold/limits.h>
#include <modelnet/swarm_ablatehold/request.h>

namespace modelnet {

bool SwarmAblateHold::Request(const std::string& name, std::string& err)
{
    return SwarmAblateHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmAblateHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmAblateHold::stored_name(const std::string& name) const
{
    return SwarmAblateHoldKeep{}.first(m_book, name);
}

std::size_t SwarmAblateHold::request_count() const
{
    return m_book.size();
}

bool SwarmAblateHold::published() const
{
    if (m_book.published()) return true;
    return m_stay.published();
}

int64_t SwarmAblateHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmAblateHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmAblateHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmAblateHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
