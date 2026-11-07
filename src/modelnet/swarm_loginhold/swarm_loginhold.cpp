// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/swarm_loginhold.h>

#include <modelnet/swarm_loginhold/keep.h>
#include <modelnet/swarm_loginhold/limits.h>
#include <modelnet/swarm_loginhold/request.h>

namespace modelnet {

bool SwarmLoginHold::Request(const std::string& name, std::string& err)
{
    return SwarmLoginHoldRequest{}.Apply(m_book, name, err);
}

bool SwarmLoginHold::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmLoginHold::stored_name(const std::string& name) const
{
    return SwarmLoginHoldKeep{}.first(m_book, name);
}

std::size_t SwarmLoginHold::request_count() const
{
    return m_book.size();
}

bool SwarmLoginHold::logged_in() const
{
    if (m_book.logged_in()) return true;
    return m_stay.logged_in();
}

int64_t SwarmLoginHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmLoginHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmLoginHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmLoginHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
