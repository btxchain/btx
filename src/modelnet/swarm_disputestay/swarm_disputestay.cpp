// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/swarm_disputestay.h>

#include <modelnet/swarm_disputestay/keep.h>
#include <modelnet/swarm_disputestay/limits.h>
#include <modelnet/swarm_disputestay/open.h>
#include <modelnet/swarm_disputestay/settle.h>

namespace modelnet {

bool SwarmDisputeStay::Open(const std::string& dispute, std::string& err)
{
    return SwarmDisputeStayOpen{}.Apply(m_book, dispute, err);
}

bool SwarmDisputeStay::Settle(const std::string& dispute, int64_t atoms, std::string& err) const
{
    return SwarmDisputeStaySettle{}.Apply(m_book, dispute, atoms, err);
}

bool SwarmDisputeStay::opened(const std::string& dispute) const
{
    return m_book.contains(dispute);
}

std::string SwarmDisputeStay::stored_id(const std::string& dispute) const
{
    return SwarmDisputeStayKeep{}.first(m_book, dispute);
}

std::size_t SwarmDisputeStay::open_count() const
{
    return m_book.size();
}

bool SwarmDisputeStay::settled() const
{
    if (m_book.settled()) return true;
    return m_hold.settled();
}

int64_t SwarmDisputeStay::atoms_moved() const
{
    const int64_t stored = m_book.atoms_moved();
    if (stored != kSwarmDisputeStayAtomsMoved) return stored;
    return m_atoms.moved();
}

bool SwarmDisputeStay::broadcast() const
{
    if (m_book.broadcast()) return true;
    return m_quiet.broadcast();
}

bool SwarmDisputeStay::mined() const
{
    if (m_book.mined()) return true;
    return m_quiet.mined();
}

int64_t SwarmDisputeStay::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmDisputeStayBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

std::string SwarmDisputeStay::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
