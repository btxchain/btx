// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/record.h>

#include <modelnet/swarm_adminhold/limits.h>

namespace modelnet {

SwarmAdminHoldRecord SwarmAdminHoldMakeRecord(const std::string& channel,
                                               int64_t refund_height,
                                               const std::vector<unsigned char>& sponsor_key)
{
    SwarmAdminHoldRecord record;
    record.channel = channel;
    record.refund_height = refund_height;
    record.sponsor_key = sponsor_key;
    return record;
}

bool SwarmAdminHoldRecordUsable(const SwarmAdminHoldRecord& record)
{
    return !record.channel.empty() &&
           record.refund_height >= kSwarmAdminHoldMinHeight &&
           record.sponsor_key.size() == kSwarmAdminHoldSponsorKeyBytes;
}

} // namespace modelnet
