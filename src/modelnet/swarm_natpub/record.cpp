// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/record.h>

#include <modelnet/swarm_natpub/limits.h>
#include <modelnet/swarm_natpub/name.h>

namespace modelnet {

SwarmNatPubRecord SwarmNatPubRecord::Make(const std::string& endpoint)
{
    SwarmNatPubRecord record;
    record.m_endpoint = SwarmNatPubName{}.copy(endpoint);
    record.m_published = kSwarmNatPubPublished;
    record.m_bytes_moved = kSwarmNatPubBytesMoved;
    record.m_connected = kSwarmNatPubConnected;
    record.m_launched = kSwarmNatPubLaunched;
    return record;
}

bool SwarmNatPubRecordUsable(const SwarmNatPubRecord& record)
{
    return !record.endpoint().empty() &&
           record.published() == kSwarmNatPubPublished &&
           record.bytes_moved() == kSwarmNatPubBytesMoved &&
           record.connected() == kSwarmNatPubConnected &&
           record.launched() == kSwarmNatPubLaunched;
}

} // namespace modelnet
