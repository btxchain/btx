// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/record.h>

#include <modelnet/swarm_ckpttrust/limits.h>
#include <modelnet/swarm_ckpttrust/name.h>

namespace modelnet {

SwarmCheckpointTrustRecord SwarmCheckpointTrustRecord::Make(const std::string& claim)
{
    SwarmCheckpointTrustRecord record;
    record.m_claim = SwarmCheckpointTrustName{}.copy(claim);
    record.m_trusted = kSwarmCheckpointTrustTrusted;
    record.m_bytes_moved = kSwarmCheckpointTrustBytesMoved;
    record.m_gpu = kSwarmCheckpointTrustGpu;
    record.m_launched = kSwarmCheckpointTrustLaunched;
    return record;
}

bool SwarmCheckpointTrustRecordUsable(const SwarmCheckpointTrustRecord& record)
{
    return !record.claim().empty() &&
           record.trusted() == kSwarmCheckpointTrustTrusted &&
           record.bytes_moved() == kSwarmCheckpointTrustBytesMoved &&
           record.gpu() == kSwarmCheckpointTrustGpu &&
           record.launched() == kSwarmCheckpointTrustLaunched;
}

} // namespace modelnet
