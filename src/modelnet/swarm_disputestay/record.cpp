// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/record.h>

#include <modelnet/swarm_disputestay/limits.h>
#include <modelnet/swarm_disputestay/name.h>

namespace modelnet {

SwarmDisputeStayRecord SwarmDisputeStayRecord::Make(const std::string& dispute)
{
    SwarmDisputeStayRecord record;
    record.m_dispute = SwarmDisputeStayName{}.copy(dispute);
    record.m_settled = kSwarmDisputeStaySettled;
    record.m_atoms_moved = kSwarmDisputeStayAtomsMoved;
    record.m_bytes_moved = kSwarmDisputeStayBytesMoved;
    record.m_broadcast = kSwarmDisputeStayBroadcast;
    record.m_mined = kSwarmDisputeStayMined;
    return record;
}

bool SwarmDisputeStayRecordUsable(const SwarmDisputeStayRecord& record)
{
    return !record.dispute().empty() &&
           record.settled() == kSwarmDisputeStaySettled &&
           record.atoms_moved() == kSwarmDisputeStayAtomsMoved &&
           record.bytes_moved() == kSwarmDisputeStayBytesMoved &&
           record.broadcast() == kSwarmDisputeStayBroadcast &&
           record.mined() == kSwarmDisputeStayMined;
}

} // namespace modelnet
