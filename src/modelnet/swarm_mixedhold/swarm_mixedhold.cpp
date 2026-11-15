// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/swarm_mixedhold.h>

#include <modelnet/swarm_mixedhold/keep.h>
#include <modelnet/swarm_mixedhold/limits.h>
#include <modelnet/swarm_mixedhold/request.h>

namespace modelnet {

bool SwarmMixedHold::Request(const std::string& name, std::string& err)
{
    return SwarmMixedHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmMixedHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmMixedHold::stored_name(const std::string& name) const
{
    return SwarmMixedHoldKeep{}.first(m_book, name);
}

std::size_t SwarmMixedHold::request_count() const
{
    return m_book.size();
}

bool SwarmMixedHold::running() const
{
    if (m_book.running()) return true;
    return m_stay.running();
}

int64_t SwarmMixedHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmMixedHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmMixedHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmMixedHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
