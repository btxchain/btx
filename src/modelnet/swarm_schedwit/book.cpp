// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/book.h>

#include <modelnet/swarm_schedwit/limits.h>

#include <string>
#include <utility>

namespace modelnet {

bool SwarmSchedWitnessBook::contains(const std::string& witness) const
{
    if (witness.empty()) return false;
    return m_witnesses.find(witness) != m_witnesses.end();
}

std::string SwarmSchedWitnessBook::witness_of(const std::string& witness) const
{
    const auto found = m_witnesses.find(witness);
    if (found == m_witnesses.end()) return {};
    return found->second.witness();
}

std::size_t SwarmSchedWitnessBook::size() const
{
    return m_witnesses.size();
}

bool SwarmSchedWitnessBook::signed_ok() const
{
    for (const auto& entry : m_witnesses) {
        if (entry.second.signed_ok()) return true;
    }
    return kSwarmSchedWitnessSignedOk;
}

int64_t SwarmSchedWitnessBook::atoms_moved() const
{
    int64_t total = kSwarmSchedWitnessAtomsMoved;
    for (const auto& entry : m_witnesses) {
        total += entry.second.atoms_moved();
    }
    return total;
}

std::string SwarmSchedWitnessBook::automatic_spend() const
{
    for (const auto& entry : m_witnesses) {
        if (entry.second.automatic_spend() != kSwarmSchedWitnessAutomaticSpend) {
            return entry.second.automatic_spend();
        }
    }
    return std::string{kSwarmSchedWitnessAutomaticSpend};
}

bool SwarmSchedWitnessBook::broadcast() const
{
    for (const auto& entry : m_witnesses) {
        if (entry.second.broadcast()) return true;
    }
    return kSwarmSchedWitnessBroadcast;
}

int64_t SwarmSchedWitnessBook::bytes_moved() const
{
    int64_t total = kSwarmSchedWitnessBytesMoved;
    for (const auto& entry : m_witnesses) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmSchedWitnessBook::gpu() const
{
    for (const auto& entry : m_witnesses) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmSchedWitnessGpu;
}

bool SwarmSchedWitnessBook::store(const std::string& witness)
{
    if (contains(witness)) return false;
    SwarmSchedWitnessRecord record = SwarmSchedWitnessRecord::Make(witness);
    if (!SwarmSchedWitnessRecordUsable(record)) return false;
    m_witnesses.emplace(witness, std::move(record));
    return true;
}

} // namespace modelnet
