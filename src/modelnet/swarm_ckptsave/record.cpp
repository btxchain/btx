// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/record.h>

#include <modelnet/swarm_ckptsave/limits.h>
#include <modelnet/swarm_ckptsave/name.h>

namespace modelnet {

SwarmCkptSaveRecord SwarmCkptSaveRecord::Make(const std::string& name)
{
    SwarmCkptSaveRecord record;
    record.m_name = SwarmCkptSaveName{}.copy(name);
    record.m_saved = kSwarmCkptSaveSaved;
    record.m_bytes_moved = kSwarmCkptSaveBytesMoved;
    record.m_gpu = kSwarmCkptSaveGpu;
    record.m_launched = kSwarmCkptSaveLaunched;
    return record;
}

bool SwarmCkptSaveRecordUsable(const SwarmCkptSaveRecord& record)
{
    return !record.name().empty() &&
           record.saved() == kSwarmCkptSaveSaved &&
           record.bytes_moved() == kSwarmCkptSaveBytesMoved &&
           record.gpu() == kSwarmCkptSaveGpu &&
           record.launched() == kSwarmCkptSaveLaunched;
}

} // namespace modelnet
