// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/swarm_guesthold.h>

#include <modelnet/swarm_guesthold/check.h>
#include <modelnet/swarm_guesthold/keep.h>
#include <modelnet/swarm_guesthold/limits.h>

namespace modelnet {

bool SwarmGuestHold::Check(const std::string& name, std::string& err)
{
    return SwarmGuestHoldCheck{}.Apply(m_book, name, err);
}

bool SwarmGuestHold::checked(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmGuestHold::stored_name(const std::string& name) const
{
    return SwarmGuestHoldKeep{}.first(m_book, name);
}

std::size_t SwarmGuestHold::check_count() const
{
    return m_book.size();
}

bool SwarmGuestHold::passed() const
{
    if (m_book.passed()) return true;
    return m_stay.passed();
}

bool SwarmGuestHold::logged_in() const
{
    if (m_book.logged_in()) return true;
    return m_stay.logged_in();
}

int64_t SwarmGuestHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmGuestHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmGuestHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmGuestHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
