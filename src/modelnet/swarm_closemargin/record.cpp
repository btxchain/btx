// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/record.h>

#include <modelnet/swarm_closemargin/limits.h>
#include <modelnet/swarm_closemargin/name.h>

#include <cstdint>

namespace modelnet {

SwarmCloseMarginHoldRecord SwarmCloseMarginHoldRecord::Make(int64_t blocks)
{
    SwarmCloseMarginHoldRecord record;
    record.m_blocks = SwarmCloseMarginHoldName{}.copy(blocks);
    record.m_shrunk = kSwarmCloseMarginHoldShrunk;
    record.m_bytes_moved = kSwarmCloseMarginHoldBytesMoved;
    record.m_gpu = kSwarmCloseMarginHoldGpu;
    record.m_launched = kSwarmCloseMarginHoldLaunched;
    record.m_mined = kSwarmCloseMarginHoldMined;
    return record;
}

bool SwarmCloseMarginHoldRecordUsable(const SwarmCloseMarginHoldRecord& record)
{
    return record.blocks() == kSwarmCloseMarginHoldMarginBlocks &&
           record.shrunk() == kSwarmCloseMarginHoldShrunk &&
           record.bytes_moved() == kSwarmCloseMarginHoldBytesMoved &&
           record.gpu() == kSwarmCloseMarginHoldGpu &&
           record.launched() == kSwarmCloseMarginHoldLaunched &&
           record.mined() == kSwarmCloseMarginHoldMined;
}

} // namespace modelnet
