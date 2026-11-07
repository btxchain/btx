// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/record.h>

#include <modelnet/swarm_guesthold/limits.h>
#include <modelnet/swarm_guesthold/name.h>

namespace modelnet {

SwarmGuestHoldRecord SwarmGuestHoldRecord::Make(const std::string& name)
{
    SwarmGuestHoldRecord record;
    record.m_name = SwarmGuestHoldName{}.copy(name);
    record.m_passed = kSwarmGuestHoldPassed;
    record.m_logged_in = kSwarmGuestHoldLoggedIn;
    record.m_bytes_moved = kSwarmGuestHoldBytesMoved;
    record.m_gpu = kSwarmGuestHoldGpu;
    record.m_launched = kSwarmGuestHoldLaunched;
    return record;
}

bool SwarmGuestHoldRecordUsable(const SwarmGuestHoldRecord& record)
{
    return !record.name().empty() &&
           record.passed() == kSwarmGuestHoldPassed &&
           record.logged_in() == kSwarmGuestHoldLoggedIn &&
           record.bytes_moved() == kSwarmGuestHoldBytesMoved &&
           record.gpu() == kSwarmGuestHoldGpu &&
           record.launched() == kSwarmGuestHoldLaunched;
}

} // namespace modelnet
