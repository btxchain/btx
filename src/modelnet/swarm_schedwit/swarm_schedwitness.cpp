// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/swarm_schedwitness.h>

#include <modelnet/swarm_schedwit/keep.h>
#include <modelnet/swarm_schedwit/limits.h>
#include <modelnet/swarm_schedwit/request.h>

namespace modelnet {

bool SwarmSchedWitness::Sign(const std::string& witness, std::string& err)
{
    return SwarmSchedWitnessRequest{}.Apply(m_book, witness, err);
}

bool SwarmSchedWitness::kept(const std::string& witness) const
{
    return m_book.contains(witness);
}

std::string SwarmSchedWitness::stored_witness(const std::string& witness) const
{
    return SwarmSchedWitnessKeep{}.first(m_book, witness);
}

std::size_t SwarmSchedWitness::sign_count() const
{
    return m_book.size();
}

bool SwarmSchedWitness::signed_ok() const
{
    if (m_book.signed_ok()) return true;
    return m_stay.signed_ok();
}

int64_t SwarmSchedWitness::atoms_moved() const
{
    if (m_book.atoms_moved() != kSwarmSchedWitnessAtomsMoved) return m_book.atoms_moved();
    return m_quiet.atoms_moved();
}

std::string SwarmSchedWitness::automatic_spend() const
{
    if (m_book.automatic_spend() != kSwarmSchedWitnessAutomaticSpend) return m_book.automatic_spend();
    return m_quiet.automatic_spend();
}

bool SwarmSchedWitness::broadcast() const
{
    if (m_book.broadcast()) return true;
    return m_quiet.broadcast();
}

int64_t SwarmSchedWitness::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmSchedWitnessBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmSchedWitness::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

} // namespace modelnet
