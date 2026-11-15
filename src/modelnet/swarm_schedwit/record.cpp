// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/record.h>

#include <modelnet/swarm_schedwit/limits.h>
#include <modelnet/swarm_schedwit/name.h>

#include <string>

namespace modelnet {

SwarmSchedWitnessRecord SwarmSchedWitnessRecord::Make(const std::string& witness)
{
    SwarmSchedWitnessRecord record;
    record.m_witness = SwarmSchedWitnessName{}.copy(witness);
    record.m_signed_ok = kSwarmSchedWitnessSignedOk;
    record.m_atoms_moved = kSwarmSchedWitnessAtomsMoved;
    record.m_automatic_spend = std::string{kSwarmSchedWitnessAutomaticSpend};
    record.m_broadcast = kSwarmSchedWitnessBroadcast;
    record.m_bytes_moved = kSwarmSchedWitnessBytesMoved;
    record.m_gpu = kSwarmSchedWitnessGpu;
    return record;
}

bool SwarmSchedWitnessRecordUsable(const SwarmSchedWitnessRecord& record)
{
    return !record.witness().empty() &&
           record.signed_ok() == kSwarmSchedWitnessSignedOk &&
           record.atoms_moved() == kSwarmSchedWitnessAtomsMoved &&
           record.automatic_spend() == kSwarmSchedWitnessAutomaticSpend &&
           record.broadcast() == kSwarmSchedWitnessBroadcast &&
           record.bytes_moved() == kSwarmSchedWitnessBytesMoved &&
           record.gpu() == kSwarmSchedWitnessGpu;
}

} // namespace modelnet
