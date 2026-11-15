// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/swarm_passhold.h>

#include <modelnet/swarm_passhold/keep.h>
#include <modelnet/swarm_passhold/limits.h>
#include <modelnet/swarm_passhold/request.h>

namespace modelnet {

bool SwarmPassHold::Request(const std::string& name, std::string& err)
{
    return SwarmPassHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmPassHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmPassHold::stored_name(const std::string& name) const
{
    return SwarmPassHoldKeep{}.first(m_book, name);
}

std::size_t SwarmPassHold::request_count() const
{
    return m_book.size();
}

bool SwarmPassHold::started() const
{
    if (m_book.started()) return true;
    return m_stay.started();
}

bool SwarmPassHold::passed() const
{
    if (m_book.passed()) return true;
    return m_stay.passed();
}

int64_t SwarmPassHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmPassHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmPassHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmPassHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
